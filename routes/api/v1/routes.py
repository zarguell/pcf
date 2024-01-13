import glob
import importlib
import logging
import os
import sys

import wtforms
from wtforms import StringField

from routes.api import api_bp as routes
from webargs.flaskparser import abort, FlaskParser
from .forms import *
from flask import jsonify, make_response, request, send_file
from system.db import Database
from system.config_load import config_dict
from system.crypto_functions import check_hash, is_valid_uuid, gen_uuid
from system.security_functions import run_function_timeout, sql_to_regexp, extract_to_regexp
from jinja2.sandbox import SandboxedEnvironment
import time
import re
from flask_wtf.csrf import CSRFProtect

from functools import wraps
import json
import email_validator
import base64
import binascii
from os import path, remove

config = config_dict()


def authenticate():
    message = {'message': "Authenticate."}
    resp = jsonify(message)

    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Basic realm="Main"'

    return resp


def ok_user_and_password(username, password):
    return username == config['security']['basic_login'] and \
           password == config['security']['basic_password']


def requires_authorization(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if config['security']['basic_auth'] == '0':
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not ok_user_and_password(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


global db
db = Database(config)
csrf = CSRFProtect()


def fail(msg, status=400):
    """
    Generates JSON error msg
    :param msg: Error message(s)
    :param status: Status code
    :return:
    """
    if not isinstance(msg, list):
        msg = [msg]
    return make_response(jsonify(dict(errors=msg)), status)


class Parser(FlaskParser):
    def handle_error(self, error, req, schema,
                     error_status_code, error_headers):
        response = fail(
            [f"Fields with errors: {', '.join(['`{}`'.format(x) for x in v])}"
             for k, v
             in error.messages.items()]
        )
        abort(response)


parser = Parser()


###############################################
#                                             #
#                  WRAPPERS                   #
#                                             #
###############################################

def check_access_token(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        access_token = ""
        if not args or 'access_token' not in args[0]:
            # some bad fix for plugin support
            if request.json:
                    if 'access_token' not in request.json:
                        abort(fail(['access_token not found!']))
                    if is_valid_uuid(request.json['access_token']):
                        access_token = request.json['access_token']
            else:
                abort(fail(['Invalid token - must be UUID!']))
        else:
            access_token = str(args[0]['access_token'])
        current_token = db.select_token(access_token)

        if not current_token:
            abort(fail(['Token not found!']))
            return

        current_token = current_token[0]

        curr_time = int(time.time())

        if curr_time > current_token['create_date'] + current_token['duration']:
            return fail(['Token expired!'])

        current_user = db.select_user_by_id(current_token['user_id'])

        if not current_user:
            return fail(['User not found!'])
        current_user = current_user[0]
        kwargs['current_user'] = current_user
        kwargs['current_token'] = current_token
        return fn(*args, **kwargs)

    return decorated_view


def check_team_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_user = kwargs['current_user']
        team_id = str(kwargs['team_id'])
        current_team = db.select_team_by_id(team_id)
        if not current_team:
            return fail(["Team not found!"])
        current_team = current_team[0]
        team_users = json.loads(current_team['users'])
        if current_user['email'] == current_team['admin_email'] or \
                current_user['id'] == current_team['admin_id'] or \
                current_user['id'] in team_users:
            kwargs['current_team'] = current_team
            return fn(*args, **kwargs)

        return fail(["User does not have access to this team!"])

    return decorated_view


def check_team_admin(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_user = kwargs['current_user']
        current_team = kwargs['current_team']
        team_users = json.loads(current_team['users'])
        if current_team['admin_id'] == current_user['id'] or \
                (current_user['id'] in team_users and
                 team_users[current_user['id']] == 'admin') or \
                current_team['admin_email'] == current_user['email']:
            return fn(*args, **kwargs)
        return fail(["User is not a team administrator"])

    return decorated_view


def check_project_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        project_id = kwargs['project_id']
        current_user = kwargs['current_user']
        current_project = db.check_user_project_access(str(project_id),
                                                       current_user['id'])
        if not current_project:
            return fail(["Project not found!"])
        kwargs['current_project'] = current_project
        return fn(*args, **kwargs)

    return decorated_view


def check_project_archived(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']

        if current_project['status'] == 0 or (current_project['end_date'] < time.time() and
                                              current_project['auto_archive'] == 1):
            if current_project['status'] == 1:
                db.update_project_status(current_project['id'], 0)
            return fail(["Project was archived!"])
        return fn(*args, **kwargs)

    return decorated_view


def check_project_host_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']
        host_id = kwargs['host_id']
        current_host = db.select_project_host(current_project['id'],
                                              str(host_id))
        if not current_host:
            return fail(["Host not found!"])
        kwargs['current_host'] = current_host[0]
        return fn(*args, **kwargs)

    return decorated_view


def check_project_task_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']
        task_id = kwargs['task_id']
        current_task = db.select_task(str(task_id), current_project['id'])
        if not current_task:
            return fail(["Task not found!"])
        kwargs['current_task'] = current_task[0]
        return fn(*args, **kwargs)

    return decorated_view


def check_project_port_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']
        port_id = str(kwargs['port_id'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(["Port not found!"])
        current_port = current_port[0]
        current_host = db.select_host_by_port_id(current_port['id'])
        if not current_host:
            return fail(["Host not found!"])
        kwargs['current_host'] = current_host[0]
        kwargs['current_port'] = current_port
        return fn(*args, **kwargs)

    return decorated_view


def check_project_network_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']
        network_id = str(kwargs['network_id'])
        current_network = db.select_network(network_id)
        if not current_network:
            return fail(["Network not found!"])
        current_network = current_network[0]
        if current_network['project_id'] != current_project['id']:
            return fail(["Network not found!"])
        kwargs['current_network'] = current_network
        return fn(*args, **kwargs)

    return decorated_view


def check_project_issue_access(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_project = kwargs['current_project']
        issue_id = str(kwargs['issue_id'])
        current_issue = db.select_issue(issue_id)
        if not current_issue:
            return fail(["Issue not found!"])
        current_issue = current_issue[0]
        if current_issue['project_id'] != current_project['id']:
            return fail(["Issue not found!"])
        kwargs['current_issue'] = current_issue
        return fn(*args, **kwargs)

    return decorated_view


def check_project_issue_poc(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        current_issue = kwargs['current_issue']
        poc_id = str(kwargs['poc_id'])
        current_poc = db.select_poc(poc_id)
        if not current_poc:
            return fail(["PoC not found!"])
        current_poc = current_poc[0]
        if current_poc['issue_id'] != current_issue['id']:
            return fail(["Wrong issue id!"])

        kwargs['current_poc'] = current_poc
        return fn(*args, **kwargs)

    return decorated_view


###############################################
#                                             #
#                   ROUTES                    #
#                                             #
###############################################

@routes.route('/api/v1/swagger_v1.0.0.json',
              methods=['GET'])
def swagger_v1():
    return send_file('routes/api/v1/swagger_v1.0.0.json')


@routes.route('/api/v1/create_token', methods=['POST'])
@requires_authorization
@parser.use_args(token_create_args, location='json')
def create_token(args):
    """
    POST /api/v1/create_token HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "name":"1234",
        "password" :"1234",
        "email" : "1234",
        "duration":123
    }

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """
    curr_user = db.select_user_by_email(args['email'])
    if not curr_user:
        return fail(["Auth error!"])
    curr_user = curr_user[0]
    if not check_hash(curr_user['password'], args['password']):
        return fail(["Auth error!"])

    token_id = db.insert_token(curr_user['id'],
                               name=args['name'],
                               create_date=int(time.time()),
                               duration=args['duration'])

    return {
        'access_token': token_id
    }


@routes.route('/api/v1/check_token', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
def check_token(args):
    """
    POST /api/v1/check_token HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token": "ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    current_token = db.select_token(str(args['access_token']))

    if not current_token:
        return fail(['Token not found!'])

    current_token = current_token[0]

    curr_time = int(time.time())

    if curr_time > current_token['create_date'] + current_token['duration']:
        return fail(['Token expired!'])

    current_user = db.select_user_by_id(current_token['user_id'])

    if not current_user:
        return fail(['User not found!'])

    return {
        'access_token': current_token['id'],
        'creation_date': current_token['create_date'],
        'duration': current_token['duration'],
        'time_left': current_token['duration'] - (
                int(time.time()) - current_token['create_date'])
    }


@routes.route('/api/v1/disable_token', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
def disable_token(args):
    """
    POST /api/v1/disable_token HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token": "ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    current_token = db.select_token(str(args['access_token']))

    if not current_token:
        return fail(['Token not found!'])

    current_token = current_token[0]

    curr_time = int(time.time())

    if curr_time > current_token['create_date'] + current_token['duration']:
        return fail(['Token expired!'])

    current_user = db.select_user_by_id(current_token['user_id'])

    if not current_user:
        return fail(['User not found!'])

    db.update_disable_token(current_token['id'])

    return {
        'status': 'ok'
    }


@routes.route('/api/v1/user/me', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
def user_info_me(args, current_user=None, current_token=None):
    """
    POST /api/v1/user/me HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    user_teams = db.select_user_teams(current_user['id'])
    j_teams = []
    for current_team in user_teams:
        team_obj = {'id': current_team['id'],
                    'name': current_team['name'],
                    'description': current_team['description'],
                    'is_admin': False}
        team_users = json.loads(current_team['users'])
        if current_team['admin_id'] == current_user['id'] or \
                (current_user['id'] in team_users and
                 team_users[current_user['id']] == 'admin') or \
                current_team['admin_email'] == current_user['email']:
            team_obj['is_admin'] = True
        j_teams.append(team_obj)

    return {
        'id': current_user['id'],
        'fname': current_user['fname'],
        'lname': current_user['lname'],
        'email': current_user['lname'],
        'company': current_user['company'],
        'teams': j_teams

    }


@routes.route('/api/v1/user/<uuid:user_id>/info', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
def user_info(args, current_user=None, current_token=None, user_id=''):
    """
    POST /api/v1/user/a400d1c6-3cad-4803-8f5f-8468d0869945 HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    test_user = db.select_user_by_id(str(user_id))

    if not test_user:
        return {'error': ['User not found!']}

    test_user = test_user[0]

    return {
        'id': test_user['id'],
        'fname': test_user['fname'],
        'lname': test_user['lname'],
        'email': test_user['lname'],
        'company': test_user['company']
    }


@routes.route('/api/v1/teams', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
def teams_list(args, current_user=None, current_token=None, user_id=''):
    """
    POST /api/v1/teams HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    user_teams = db.select_user_teams(current_user['id'])
    j_teams = []
    for current_team in user_teams:
        team_obj = {'id': current_team['id'],
                    'name': current_team['name'],
                    'description': current_team['description'],
                    'is_admin': False}
        team_users = json.loads(current_team['users'])
        if current_team['admin_id'] == current_user['id'] or \
                (current_user['id'] in team_users and
                 team_users[current_user['id']] == 'admin') or \
                current_team['admin_email'] == current_user['email']:
            team_obj['is_admin'] = True
        j_teams.append(team_obj)
    return {'teams': j_teams}


@routes.route('/api/v1/team/<uuid:team_id>/info', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_team_access
def teams_info(args, current_user=None, current_token=None, user_id='',
               current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    is_admin = False
    team_users = json.loads(current_team['users'])

    if current_team['admin_id'] == current_user['id'] or \
            (current_user['id'] in team_users and
             team_users[current_user['id']] == 'admin') or \
            current_team['admin_email'] == current_user['email']:
        is_admin = True

    team_j = {
        'id': current_team['id'],
        'name': current_team['name'],
        'description': current_team['description'],
        'admin_email': current_team['admin_email'],
        'admin_id': current_team['admin_id'],
        'is_admin': is_admin
    }

    return team_j


@routes.route('/api/v1/team/<uuid:team_id>/users', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_team_access
def team_users_list(args, current_user=None, current_token=None, user_id='',
                    current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/users HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    is_admin = False
    team_users = json.loads(current_team['users'])

    users_obj = []

    for user_id in team_users:
        sel_user = db.select_user_by_id(user_id)[0]
        user_obj = {
            'id': sel_user['id'],
            'email': sel_user['email'],
            'fname': sel_user['fname'],
            'lname': sel_user['lname'],
            'company': sel_user['company'],
            'is_admin': False
        }

        if current_team['admin_id'] == sel_user['id'] or \
                (sel_user['id'] in team_users and
                 team_users[sel_user['id']] == 'admin') or \
                current_team['admin_email'] == sel_user['email']:
            user_obj['is_admin'] = True
        users_obj.append(user_obj)

    return {'users': users_obj}


@routes.route('/api/v1/team/<uuid:team_id>/projects', methods=['POST'])
@requires_authorization
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_team_access
def team_projects_list(args, current_user=None, current_token=None, user_id='',
                       current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/projects HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {"access_token":"ad236cdb-f645-456c-918c-dd8d8085ae95"}
    """

    team_projects = db.select_team_projects(current_team['id'])

    projects_obj = []
    for project in team_projects:
        status = "active"
        if project['end_date'] < int(time.time()) and project['auto_archive']:
            status = "archived"
        project_obj = {
            'name': project['name'],
            'description': project['description'],
            'type': project['type'],
            'scope': project['scope'],
            'start_date': project['start_date'],
            'end_date': project['end_date'],
            'status': status,
            'admin_id': project['admin_id'],
            'folder': project['folder'],
            'report_title': project['folder']
        }
        projects_obj.append(project_obj)
    return {'projects': projects_obj}


@routes.route('/api/v1/team/<uuid:team_id>/logs', methods=['POST'])
@requires_authorization
@parser.use_args(project_logs_args, location='json')
@check_access_token
@check_team_access
def team_logs_list(args, current_user=None, current_token=None, user_id='',
                   current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/logs HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "limit":2,
        "offset" :0
    }
    """

    team_logs = db.get_log_by_team_id(current_team['id'],
                                      limit=args['limit'],
                                      offset=args['offset'])

    logs_obj = []
    for log in team_logs:
        log_obj = {
            'id': log['id'],
            'description': log['description'],
            'date': log['date'],
            'project': log['project'],
            'user_id': log['user_id']
        }
        logs_obj.append(log_obj)
    return {'logs': logs_obj}


@routes.route('/api/v1/team/<uuid:team_id>/info/update', methods=['POST'])
@requires_authorization
@parser.use_args(project_change_info_args, location='json')
@check_access_token
@check_team_access
@check_team_admin
def team_update_info(args, current_user=None, current_token=None, user_id='',
                     current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/info/update HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "name":"redteam",
        "description" :"Cool team"
    }
    """
    team_name = current_team['name']
    team_description = current_team['description']
    team_email = current_team['admin_email']
    if 'name' in args:
        team_name = args['name']
    if 'description' in args:
        team_description = args['description']
    if 'admin_email' in args:
        team_email = args['admin_email']

    db.update_team_info(current_team['id'], team_name, team_email,
                        team_description, current_user['id'])

    return {'status': 'ok'}


@routes.route('/api/v1/team/<uuid:team_id>/users/add', methods=['POST'])
@requires_authorization
@parser.use_args(project_add_user_args, location='json')
@check_access_token
@check_team_access
@check_team_admin
def team_add_user(args, current_user=None, current_token=None, user_id='',
                  current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/users/add HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "email":"iljashaposhnikov@gmail.com",
        "is_admin" :false
    }
    """
    team_users_ids = [x for x in json.loads(current_team['users'])]
    team_users_ids += [current_team['admin_id']]
    if args['email'] == current_team['admin_email']:
        return fail(['User is already in team!'])
    add_user = db.select_user_by_email(args['email'])
    if not add_user:
        return fail(['Email does not exist!'])
    add_user = add_user[0]
    if add_user['id'] in team_users_ids:
        return fail(['User is already in team!'])
    role = 'tester'
    if args['is_admin']:
        role = 'admin'
    db.update_new_team_user(current_team['id'], add_user['email'], role=role)
    return {'status': 'ok'}


@routes.route('/api/v1/team/<uuid:team_id>/users/delete', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(project_user_action_args, location='json')
@check_access_token
@check_team_access
@check_team_admin
def team_delete_user(args, current_user=None, current_token=None, user_id='',
                     current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/users/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "user_id":"c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    message = db.delete_user_from_team_safe(current_team['id'],
                                       str(args['user_id']),
                                       current_user['id'])
    if message:
        return fail([message])
    return {'status': 'ok'}


@routes.route('/api/v1/team/<uuid:team_id>/users/set_admin', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(project_user_action_args, location='json')
@check_access_token
@check_team_access
@check_team_admin
def team_set_admin(args, current_user=None, current_token=None, user_id='',
                   current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/users/set_admin HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "user_id":"c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    message = db.set_admin_team_user(current_team['id'],
                                     str(args['user_id']),
                                     current_user['id'])
    if message:
        return fail([message])
    return {'status': 'ok'}


@routes.route('/api/v1/team/<uuid:team_id>/users/devote', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(project_user_action_args, location='json')
@check_access_token
@check_team_access
@check_team_admin
def team_devote_user(args, current_user=None, current_token=None, user_id='',
                     current_team=None, team_id=None):
    """
    POST /api/v1/team/ad236cdb-f645-456c-918c-dd8d8085ae95/users/devote HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "user_id":"c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    message = db.devote_user_from_team(current_team['id'],
                                       str(args['user_id']),
                                       current_user['id'])
    if message:
        return fail([message])
    return {'status': 'ok'}


@routes.route('/api/v1/projects', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
def user_projects(args, current_user=None, current_token=None, user_id=''):
    """
    POST /api/v1/projects HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    user_projects_list = db.select_user_projects(current_user['id'])
    projects_list = []
    for current_project in user_projects_list:
        project_obj = {
            'id': current_project['id'],
            'name': current_project['name'],
            'description': current_project['description'],
            'type': current_project['type'],
            'scope': current_project['scope'],
            'start_date': current_project['start_date'],
            'end_date': current_project['end_date'],
            'folder': current_project['folder'],
            'report_title': current_project['report_title'],
            'status': 'active' if current_project['status'] else 'archived',
            'admin_id': current_project['admin_id']
        }
        project_testers_ids = json.loads(current_project['testers'])
        project_testers = []
        for project_tester_id in project_testers_ids:
            tester_data = db.select_user_by_id(project_tester_id)[0]
            project_tester_obj = {
                'id': tester_data['id'],
                'email': tester_data['email'],
                'fname': tester_data['fname'],
                'lname': tester_data['lname'],
                'company': tester_data['company'],
                'is_admin': (tester_data['id'] == current_project['admin_id'])
            }
            project_testers.append(project_tester_obj)
        project_obj['testers'] = project_testers

        project_teams_ids = json.loads(current_project['teams'])
        project_teams = []
        for team_id in project_teams_ids:
            current_team = db.select_team_by_id(team_id)[0]
            current_team_obj = {
                'id': current_team['id'],
                'name': current_team['name'],
                'description': current_team['description'],
                'admin_email': current_team['admin_email'],
                'admin_id': current_team['admin_id']
            }
            project_teams.append(current_team_obj)

        project_obj['teams'] = project_teams
        projects_list.append(project_obj)

    return {'projects': projects_list}


@routes.route('/api/v1/project/new', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_project_args, location='json')
@check_access_token
def new_project(args, current_user=None, current_token=None, user_id=''):
    """
    POST /api/v1/project/new HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 74

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "name": "hello there!",
        "description": "wefweewdf",
        "type":"pentest",
        "scope":"hello scope",
        "start_date" : 1597104000,
        "end_date":32512492800,
        "folder": "test name",
        "report_title": "Report official name",
        "auto_archive": false,
        "teams":[
            "0256a838-0a71-4fc0-8456-538e1032080b"
        ],
        "testers":[
            "2fdcbbf0-170f-46e6-92f9-2ff0c46f5094",
            "7d07be04-adc5-4089-b89e-9a6ab7a16e13",
            "a400d1c6-3cad-4803-8f5f-8468d0869945"
        ]
    }
    """

    name = args['name']
    description = args['description']
    type = args['type']
    scope = args['scope']
    start_date = args['start_date']
    end_date = args['end_date']
    auto_archive = args['auto_archive']
    teams = [str(team_id) for team_id in args['teams']]
    testers = [str(user_id) for user_id in args['testers']]
    folder = args['folder']
    report_title = args['report_title']

    for team_id in teams:
        current_team = db.select_team_by_id(team_id)
        if not current_team:
            return fail(['Team {} does not exist!'.format(team_id)])
        elif current_user['id'] not in current_team[0]['users']:
            fail(['User does not have access to team {}!'.format(team_id)])

    # check user relationship
    teams_array = db.select_user_teams(current_user['id'])
    for user_id in testers:
        found = 0
        for team in teams_array:
            if user_id in team['users']:
                found = 1
        if not found or not db.select_user_by_id(user_id):
            return fail(['User {} not found!'.format(user_id)])

    if current_user['id'] not in testers:
        testers.append(current_user['id'])

    project_id = db.insert_new_project(name,
                                       description,
                                       type,
                                       scope,
                                       start_date,
                                       end_date,
                                       auto_archive,
                                       testers,
                                       teams,
                                       current_user['id'],
                                       current_user['id'],
                                       folder,
                                       report_title)
    return {'project_id': str(project_id)}


@routes.route('/api/v1/project/<uuid:project_id>/settings', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_settings(args, current_user=None, current_token=None, user_id='',
                     project_id=None, current_project=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/settings HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {"access_token": "feeae1ef-4d70-4bed-87c1-198241bf551b"}
    """
    project_obj = {
        'id': current_project['id'],
        'name': current_project['name'],
        'description': current_project['description'],
        'type': current_project['type'],
        'scope': current_project['scope'],
        'start_date': current_project['start_date'],
        'end_date': current_project['end_date'],
        'status': 'active' if current_project['status'] else 'archived',
        'admin_id': current_project['admin_id'],
        'folder': current_project['folder'],
        'report_title': current_project['report_title']
    }
    project_testers_ids = json.loads(current_project['testers'])
    project_testers = []
    for project_tester_id in project_testers_ids:
        tester_data = db.select_user_by_id(project_tester_id)[0]
        project_tester_obj = {
            'id': tester_data['id'],
            'email': tester_data['email'],
            'fname': tester_data['fname'],
            'lname': tester_data['lname'],
            'company': tester_data['company'],
            'is_admin': (tester_data['id'] == current_project['admin_id'])
        }
        project_testers.append(project_tester_obj)
    project_obj['testers'] = project_testers

    project_teams_ids = json.loads(current_project['teams'])
    project_teams = []
    for team_id in project_teams_ids:
        current_team = db.select_team_by_id(team_id)[0]
        current_team_obj = {
            'id': current_team['id'],
            'name': current_team['name'],
            'description': current_team['description'],
            'admin_email': current_team['admin_email'],
            'admin_id': current_team['admin_id']
        }
        project_teams.append(current_team_obj)

    project_obj['teams'] = project_teams

    return project_obj


@routes.route('/api/v1/project/<uuid:project_id>/settings/edit',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(project_update_args, location='json')
@check_access_token
@check_project_access
def project_settings_edit(args, current_user=None, current_token=None,
                          user_id='',
                          project_id=None, current_project=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/settings/edit HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "name": "wefwefwef",
        "description": "wefweewdf",
        "type":"pentest",
        "scope":"hello scope",
        "start_date" : 1597104000,
        "end_date":32512492800,
        "auto_archive": True,
        "folder": "redteam",
        "report_title": "Official report name",
        "teams":[
            "0256a838-0a71-4fc0-8456-538e1032080b"
        ],
        "testers":[
            "2fdcbbf0-170f-46e6-92f9-2ff0c46f5094",
            "7d07be04-adc5-4089-b89e-9a6ab7a16e13",
            "a400d1c6-3cad-4803-8f5f-8468d0869945"
        ]
    }
    """

    name = current_project['name']
    if args['name'] != None:
        name = args['name']
    description = current_project['description']
    if args['description'] != None:
        description = args['description']
    folder = current_project['folder']
    if args['folder'] != None:
        folder = args['folder']
    report_title = current_project['report_title']
    if args['report_title'] != None:
        report_title = args['report_title']
    type = current_project['type']
    if args['type'] != None:
        type = args['type']
    scope = current_project['scope']
    if args['scope'] != None:
        scope = args['scope']
    start_date = current_project['start_date']
    if args['start_date'] != None:
        start_date = args['start_date']
    end_date = current_project['end_date']
    if args['end_date'] != None:
        end_date = args['end_date']
    status = current_project['status']
    if args['status'] != None:
        status = int(args['status'] == 'active')
    auto_archive = current_project['auto_archive']
    if args['auto_archive'] != None:
        auto_archive = int(args['auto_archive'])

    teams = json.loads(current_project['teams'])
    if args['teams'] != None:
        teams = [str(team_id) for team_id in args['teams']]

    for team_id in teams:
        current_team = db.select_team_by_id(team_id)
        if not current_team:
            return fail(['Team {} does not exist!'.format(team_id)])
        elif current_user['id'] not in current_team[0]['users']:
            fail(['User does not have access to team {}!'.format(team_id)])

    testers = json.loads(current_project['testers'])
    if args['testers'] != None:
        testers = [str(user_id) for user_id in args['testers']]

    # check user relationship
    teams_array = db.select_user_teams(current_user['id'])
    for user_id in testers:
        found = 0
        for team in teams_array:
            if user_id in team['users']:
                found = 1
        if not found or not db.select_user_by_id(user_id):
            return fail(['User {} not found!'.format(user_id)])

    # change status
    db.update_project_status(current_project['id'], status)
    if status and (args['status'] != None):
        db.update_project_autoarchive(current_project['id'], 0)

    project_id = db.update_project_settings(current_project['id'],
                                            name,
                                            description,
                                            type,
                                            scope,
                                            start_date,
                                            end_date,
                                            auto_archive,
                                            testers,
                                            teams,
                                            folder,
                                            report_title)
    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/hosts',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_hosts_list(args, current_user=None, current_token=None,
                       user_id='',
                       project_id=None, current_project=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/hosts HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    hosts_array = []
    hosts_list = db.select_project_hosts(current_project['id'])
    for current_host in hosts_list:
        host_obj = {
            'id': current_host['id'],
            'ip': current_host['ip'],
            'description': current_host['comment'],
            'threats': json.loads(current_host['threats']),
            'os': current_host['os']
        }

        # hostnames
        hostnames = db.select_ip_hostnames(current_host['id'])
        hostnames_arr = []
        for current_hostname in hostnames:
            hostname_obj = {
                'id': current_hostname['id'],
                'hostname': current_hostname['hostname'],
                'description': current_hostname['description'],
            }
            hostnames_arr.append(hostname_obj)
        host_obj['hostnames'] = hostnames_arr

        # issues
        issues_array = [issue['id'] for issue in
                        db.select_host_issues(current_host['id'])]
        host_obj['issues'] = issues_array

        hosts_array.append(host_obj)

    return {'hosts': hosts_array}


@routes.route('/api/v1/project/<uuid:project_id>/host/<uuid:host_id>/info',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_host_access
def project_host_info(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None,
                      host_id=None, current_host=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/host/ffa5fc47-28ef-4c13-88c6-a9accfb401b2/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """
    host_obj = {
        'id': current_host['id'],
        'ip': current_host['ip'],
        'description': current_host['comment'],
        'threats': json.loads(current_host['threats']),
        'os': current_host['os']
    }

    # hostnames
    hostnames = db.select_ip_hostnames(current_host['id'])
    hostnames_arr = []
    for current_hostname in hostnames:
        hostname_obj = {
            'id': current_hostname['id'],
            'hostname': current_hostname['hostname'],
            'description': current_hostname['description']
        }
        hostnames_arr.append(hostname_obj)
    host_obj['hostnames'] = hostnames_arr

    # issues
    issues_array = [issue['id'] for issue in
                    db.select_host_issues(current_host['id'])]
    host_obj['issues'] = issues_array

    # ports
    ports_array = []
    ports_list = db.select_host_ports(current_host['id'])
    for current_port in ports_list:
        port_obj = {
            'id': current_port['id'],
            'port': current_port['port'],
            'is_tcp': (current_port['is_tcp'] == 1),
            'service': current_port['service'],
            'description': current_port['description']
        }
        ports_array.append(port_obj)

    host_obj['ports'] = ports_array

    return host_obj


@routes.route('/api/v1/project/<uuid:project_id>/host/<uuid:host_id>/edit',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(host_edit_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_host_access
def project_host_edit(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None,
                      host_id=None, current_host=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/host/ffa5fc47-28ef-4c13-88c6-a9accfb401b2/edit HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "description": "123",
        "threats":["high","medium","low", "info","check", "checked", "noscope", "recheck", "firewall", "offline", "inwork", "scope", "critical", "slow"],
        "os": "Windows 7"
    }
    """

    description = current_host['comment']
    if args['description'] != None:
        description = args['description']
    threats = json.loads(current_host['threats'])
    if args['threats'] != None:
        threats = args['threats']

    os = current_host['os']
    if args['os'] != None:
        os = args['os']

    db.update_host_comment_threats(current_host['id'],
                                   description,
                                   threats,
                                   os)

    return {"status": "ok"}


@routes.route('/api/v1/project/<uuid:project_id>/host/new',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_host_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_new_host(args, current_user=None, current_token=None,
                     user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/host/new HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "ip": "5.5.5.5",
        "description": "coool"
    }
    """
    host = db.select_project_host_by_ip(current_project['id'], str(args['ip']))
    if not host:
        host_id = db.insert_host(current_project['id'], str(args['ip']),
                                 current_user['id'],
                                 args['description'])
        return {'host_id': host_id}
    return fail(["Host already exist!"])


@routes.route('/api/v1/project/<uuid:project_id>/host/<uuid:host_id>/delete',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_host_access
def project_host_delete(args, current_user=None, current_token=None,
                        user_id='', project_id=None, current_project=None,
                        host_id=None, current_host=None):
    """
    POST /api/v1/project/a400d1c6-3cad-4803-8f5f-8468d0869945/host/ffa5fc47-28ef-4c13-88c6-a9accfb401b2/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 56

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    db.delete_host_safe(current_project['id'], current_host['id'])

    return {"status": "ok"}


@routes.route('/api/v1/project/<uuid:project_id>/port/<uuid:port_id>/info',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_port_access
def project_port_info(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None,
                      host_id=None, current_host=None, port_id=None,
                      current_port=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/port/a71fa573-a23a-4313-918e-f52468dcd527/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 58

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    port_issues = db.select_port_issues(current_port['id'])

    port_obj = {
        'id': current_port['id'],
        'port': current_port['port'],
        'is_tcp': (current_port['is_tcp'] == 1),
        'service': current_port['service'],
        'description': current_port['description'],
        'host_id': current_host['id'],
        'issues': [issue['id'] for issue in port_issues]
    }
    return port_obj


@routes.route('/api/v1/project/<uuid:project_id>/port/<uuid:port_id>/edit',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(port_edit_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_port_access
def project_port_edit(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None,
                      host_id=None, current_host=None, port_id=None,
                      current_port=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/port/d9360618-0cec-4198-a6c0-523c71968654/edit HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 106

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b",
        "service"  :"1234",
        "description":"cooool"
    }
    """

    service = current_port['service']
    if args['service'] != None:
        service = args['service']
    description = current_port['description']
    if args['description'] != None:
        description = args['description']

    db.update_port_proto_description(current_port['id'], service, description)
    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/port/<uuid:port_id>/delete',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(port_edit_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_port_access
def project_port_delete(args, current_user=None, current_token=None,
                        user_id='', project_id=None, current_project=None,
                        host_id=None, current_host=None, port_id=None,
                        current_port=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/port/d9360618-0cec-4198-a6c0-523c71968654/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 106

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    db.delete_port_safe(current_port['id'])

    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/port/new',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_port_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_new_port(args, current_user=None, current_token=None,
                     user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/port/new HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 106

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    current_host = db.select_project_host(current_project['id'],
                                          str(args['host_id']))
    if not current_host:
        return fail(['Host not found!'])

    current_host = current_host[0]

    port_id = db.insert_host_port(current_host['id'], args['port'],
                                  int(args['is_tcp']),
                                  args['service'],
                                  args['description'], current_user['id'],
                                  current_project['id'])
    if port_id == 'exist':
        return fail(['Port already exists!'])

    return {'port_id': port_id}


@routes.route('/api/v1/project/<uuid:project_id>/networks',
              methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_networks_list(args, current_user=None, current_token=None,
                          user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/networks HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 106

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    networks = db.select_project_networks(current_project['id'])
    networks_array = []
    for current_network in networks:
        hosts = db.search_hostlist(current_project['id'],
                                   network=current_network['id'])
        network_obj = {
            'id': current_network['id'],
            'ip': current_network['ip'],
            'mask': current_network['mask'],
            'description': current_network['comment'],
            'is_ipv6': (current_network['is_ipv6'] == 1),
            'asn': int(current_network['asn'] or 0),
            'hosts': [host['id'] for host in hosts],
            'internal_ip': current_network['internal_ip'],
            'access_from': json.loads(current_network['access_from']),
            'cmd': current_network['cmd'],
            'name': current_network['name']
        }
        networks_array.append(network_obj)

    return {'networks': networks_array}


@routes.route(
    '/api/v1/project/<uuid:project_id>/network/<uuid:network_id>/info',
    methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_network_access
def project_network_info(args, current_user=None, current_token=None,
                         user_id='', project_id=None, current_project=None,
                         network_id=None, current_network=None):
    """
    POST /api/v1/project/74ebd1a1-c10d-428d-8180-8c1d77272d1a/network/d34baf3e-aeb6-4bc6-bb8e-9a6d39d9a89b/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 58

    {
        "access_token": "c982b640-c279-48ea-ba09-970338c6790b"
    }
    """

    hosts = db.search_hostlist(current_project['id'],
                               network=current_network['id'])

    access_from = json.loads(current_network['access_from'])

    network_obj = {
        'id': current_network['id'],
        'ip': current_network['ip'],
        'mask': current_network['mask'],
        'description': current_network['comment'],
        'is_ipv6': (current_network['is_ipv6'] == 1),
        'asn': int(current_network['asn'] or 0),
        'hosts': [host['id'] for host in hosts],
        'internal_ip': current_network['internal_ip'],
        'access_from': json.loads(current_network['access_from']),
        'cmd': current_network['cmd'],
        'name': current_network['name']
    }

    return network_obj


@routes.route(
    '/api/v1/project/<uuid:project_id>/network/<uuid:network_id>/edit',
    methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(network_edit_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_network_access
def project_network_edit(args, current_user=None, current_token=None,
                         user_id='', project_id=None, current_project=None,
                         network_id=None, current_network=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/network/2f4629ba-09af-4d64-9b01-625f9ae913f4/edit HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "description"  :"1234",
        "ip":"10.0.0.0",
        "mask": 24,
        "asn": 1234,
        "name": "test network",
        "internal_ip": "10.0.0.100",
        "cmd": "ssh -D 8888 root@localhost",
        "access_from": {
            "6e61925d-891e-4009-8cda-c9b7d78efeeb":["0",
            "0a8796a1-6cc8-4063-a09c-6fdff379cf4c"
            ]
        }
    }
    """

    description = current_network['comment']
    if args['description'] != None:
        description = args['description']

    name = current_network['name']
    if args['name'] != None:
        name = args['name']

    ip = current_network['ip']
    if args['ip'] != None:
        ip = str(args['ip'])

    mask = int(current_network['mask'])
    if args['mask'] != None:
        mask = int(args['mask'])

    asn = int(current_network['asn'])
    if args['asn'] != None:
        asn = int(args['asn'])

    internal_ip = current_network['internal_ip']
    if args['internal_ip'] != None:
        internal_ip = args['internal_ip']

    cmd = current_network['cmd']
    if args['cmd'] != None:
        cmd = args['cmd']

    access_from = json.loads(current_network['access_from'])
    if args['access_from'] != None:
        access_from = args['access_from']

    is_ipv6 = ':' in ip

    if mask > 32 and not is_ipv6:
        return fail(['Mask too large for IPv4!'])

    # check if network exists
    exists_networks = db.select_project_network_by_ip(current_project['id'], ip, mask)
    for network in exists_networks:
        if network['id'] != current_network['id']:
            return fail(['Network already exists!'])

    # check port_id variable
    for port_id in access_from:
        if not is_valid_uuid(port_id):
            return fail(['Invalid port UUID!'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(['Some ports are not in project!'])
        current_port = current_port[0]
        if port_id in access_from:
            for hostname_id in access_from[port_id]:
                if hostname_id != "0":
                    if not is_valid_uuid(hostname_id):
                        return fail(['Invalid hostname UUID!'])
                    hostnames = db.select_hostname(hostname_id)
                    if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                        return fail(['Invalid hostname UUID!'])

    db.update_network(current_network['id'],
                      current_project['id'],
                      ip,
                      mask,
                      asn,
                      description,
                      is_ipv6,
                      internal_ip,
                      cmd,
                      access_from,
                      name)

    return {'status': 'ok'}


@routes.route(
    '/api/v1/project/<uuid:project_id>/network/create',
    methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(network_create_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_network_create(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/network/create HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "description"  :"1234",
        "ip":"10.0.0.0",
        "mask": 24,
        "asn": 1234,
        "internal_ip": "10.0.0.100",
        "cmd": "ssh -D 8888 root@localhost",
        "name": "Test network",
        "access_from": {
            "6e61925d-891e-4009-8cda-c9b7d78efeeb":["0",
            "0a8796a1-6cc8-4063-a09c-6fdff379cf4c"
            ]
        }
    }
    """

    description = args['description']
    ip = str(args['ip'])
    mask = int(args['mask'])
    asn = int(args['asn'])
    name = int(args['name'])
    internal_ip = args['internal_ip']
    cmd = args['cmd']
    access_from = args['access_from']
    is_ipv6 = ':' in ip

    if mask > 32 and not is_ipv6:
        return fail(['Mask too large for IPv4!'])

    # check if network exists
    exists_networks = db.select_project_network_by_ip(current_project['id'], ip, mask)
    for network in exists_networks:
        return fail(['Network already exists!'])

    # check port_id variable
    for port_id in access_from:
        if not is_valid_uuid(port_id):
            return fail(['Invalid port UUID!'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(['Some ports are not in project!'])
        current_port = current_port[0]
        for hostname_id in access_from[port_id]:
            if hostname_id != "0":
                if not is_valid_uuid(hostname_id):
                    return fail(['Invalid hostname UUID!'])
                hostnames = db.select_hostname(hostname_id)
                if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                    return fail(['Invalid hostname UUID!'])

    network_id = db.insert_new_network(ip, mask,
                                       asn, description,
                                       current_project['id'],
                                       current_user['id'], is_ipv6,
                                       internal_ip, cmd, access_from, name)

    return {'status': 'ok', 'network_id': str(network_id)}


@routes.route(
    '/api/v1/project/<uuid:project_id>/network/<uuid:network_id>/delete',
    methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_network_access
def project_network_delete(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None,
                           network_id=None, current_network=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/network/2f4629ba-09af-4d64-9b01-625f9ae913f4/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    db.delete_network_safe(current_network['id'])
    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/issues/list', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_issues_list(args, current_user=None, current_token=None,
                        user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/list HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    issues = db.select_project_issues(current_project['id'])
    issues_list = {
        'issues': []
    }
    for issue in issues:
        issue_obj = {
            "issue_id": issue["id"],
            "name": issue["name"],
            "cvss": issue["cvss"],
            "url_path": issue["url_path"],
            "description": issue["description"],
            "cve": issue["cve"],
            "cwe": issue["cwe"],
            "status": issue["status"],
            "fix": issue["fix"],
            "param": issue["param"],
            "type": issue["type"],
            "services": json.loads(issue['services']),
            "technical": issue["technical"],
            "risks": issue["risks"],
            "references": issue["references"],
            "intruder": issue["intruder"],
            "fields": json.loads(issue["fields"])
        }
        issues_list['issues'].append(issue_obj)
    return issues_list


@routes.route('/api/v1/project/<uuid:project_id>/issues/search', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(search_project_issues, location='json')
@check_access_token
@check_project_access
def project_issues_search(args, current_user=None, current_token=None,
                          user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/search HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "issue_id": "%test%",
        "name": "%test%",
        "cvss": "%test%",
        "url_path": "%test%",
        "description": "%test%",
        "cve": "%test%",
        "cwe": "%test%",
        "status": "%test%",
        "fix": "%test%",
        "param": "%test%",
        "type": "%test%",
        "technical": "%test%",
        "risks": "%test%",
        "references": "%test%",
        "intruder": "%test%",
        "fields": { "nessus_id": "%1234%" }
    }
    """

    issues = db.search_project_issues(current_project['id'], args['name'],
                                      args['cvss'], args['url_path'],
                                      args['description'], args['cve'],
                                      args['cwe'], args['status'],
                                      args['fix'], args['param'],
                                      args['type'], args['technical'],
                                      args['risks'], args['user_id'],
                                      args['references'],
                                      args['intruder'],
                                      args['fields'])
    issues_list = {
        'issues': []
    }
    for issue in issues:
        issue_obj = {
            "issue_id": issue["id"],
            "name": issue["name"],
            "cvss": issue["cvss"],
            "url_path": issue["url_path"],
            "description": issue["description"],
            "cve": issue["cve"],
            "cwe": issue["cwe"],
            "status": issue["status"],
            "fix": issue["fix"],
            "param": issue["param"],
            "type": issue["type"],
            "services": json.loads(issue['services']),
            "technical": issue["technical"],
            "risks": issue["risks"],
            "references": issue["references"],
            "intruder": issue["intruder"],
            "fields": json.loads(issue["fields"])
        }
        issues_list['issues'].append(issue_obj)
    return issues_list


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/info', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_issue_access
def project_issue_info(args, current_user=None, current_token=None,
                       user_id='', project_id=None, current_project=None, issue_id='', current_issue=None
                       ):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/5c16f0de-dd80-4ffc-952f-4ed3f3e7d657/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    issue_pocs = db.select_issue_pocs(current_issue['id'])

    issue_obj = {
        "name": current_issue["name"],
        "cvss": current_issue["cvss"],
        "url_path": current_issue["url_path"],
        "description": current_issue["description"],
        "cve": current_issue["cve"],
        "technical": current_issue["technical"],
        "risks": current_issue["risks"],
        "references": current_issue["references"],
        "intruder": current_issue["intruder"],
        "cwe": current_issue["cwe"],
        "status": current_issue["status"],
        "fix": current_issue["fix"],
        "param": current_issue["param"],
        "type": current_issue["type"],
        "services": json.loads(current_issue['services']),
        "pocs": {poc['id']: {'priority': int(poc['priority'])} for poc in issue_pocs},
        "fields": json.loads(current_issue["fields"])
    }

    return issue_obj


@routes.route('/api/v1/project/<uuid:project_id>/issues/create', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(issue_create_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_issue_create(args, current_user=None, current_token=None,
                         user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/create HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 413

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "name":"12134",
        "cvss" :10,
        "url_path"  :"/123/",
        "description": "test description",
        "cve":"CVE-2020-1234",
        "cwe":123,
        "status":"need to recheck",
        "technical": "<script>alert();</script>",
        "risks": "Database may be dropped",
        "references": "http://test.com",
        "intruder": "Internal",
        "fix":"filter params",
        "type":"custom",
        "param" :"GET id=1",
        "services":       {"6e61925d-891e-4009-8cda-c9b7d78efeeb":["0","0a8796a1-6cc8-4063-a09c-6fdff379cf4c"]	},
        "fields": {
            "nessus_id": {
              "type": "number",
              "val": 1337
            }
        },
        "dublicate_find": true
    }
    """
    name = args['name']
    if name == '':
        return fail(['Name must not be empty!'])
    cvss = args['cvss']
    url_path = args['url_path']
    description = args['description']
    cve = args['cve']
    cwe = args['cwe']
    status = args['status']
    fix = args['fix']
    param = args['param']
    services = args['services']
    issue_type = args["type"]
    technical = args["technical"]
    risks = args["risks"]
    references = args["references"]
    intruder = args["intruder"]
    additional_fields = args["fields"]

    # check port_id variable
    for port_id in services:
        if not is_valid_uuid(port_id):
            return fail(['Invalid port UUID!'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(['Some ports are not in project!'])
        current_port = current_port[0]
        for hostname_id in services[port_id]:
            if hostname_id != "0":
                if not is_valid_uuid(hostname_id):
                    return fail(['Invalid hostname UUID!'])
                hostnames = db.select_hostname(hostname_id)
                if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                    return fail(['Invalid hostname UUID!'])

    # Add additional fields
    add_fields_dict = {}
    for field_name in additional_fields:
        field_type = additional_fields[field_name]['type']
        field_value = additional_fields[field_name]['val']
        if field_type in ["text", "number", "float", "boolean"]:
            # add text field
            try:
                if field_type == "text":
                    type_func = str
                elif field_type == "number":
                    type_func = int
                elif field_type == "float":
                    type_func = float
                elif field_type == "boolean":
                    type_func = lambda x: bool(int(x))
                add_fields_dict[field_name] = {
                    'val': type_func(field_value),
                    'type': field_type
                }
            except:
                pass

    if args['dublicate_find']:
        issue_id = db.insert_new_issue_no_dublicate(name, description, url_path, cvss,
                                                    current_user['id'], services, status,
                                                    current_project['id'], cve, cwe, issue_type, fix, param,
                                                    technical, risks, references, intruder)
        old_fields = json.loads(db.select_issue(issue_id)[0]["fields"])
        for field_name in add_fields_dict:
            old_fields[field_name] = add_fields_dict[field_name]

        if add_fields_dict:
            db.update_issue_fields(issue_id, old_fields)

    else:
        issue_id = db.insert_new_issue(name, description, url_path,
                                       cvss, current_user['id'], services, status,
                                       current_project['id'], cve, cwe, issue_type,
                                       fix, param, fields=add_fields_dict, technical=technical, risks=risks,
                                       references=references, intruder=intruder)

    return {"status": "ok", "issue_id": issue_id}


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/edit', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(issue_edit_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_issue_access
def project_issue_edit(args, current_user=None, current_token=None,
                       user_id='', project_id=None, current_project=None, issue_id='', current_issue=None
                       ):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/3ade0ed-ea2d-4812-9676-8bdcf5b7412c/edit HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 413

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "name":"12134",
        "cvss" :10,
        "url_path"  :"/123/",
        "description": "test description",
        "cve":"CVE-2020-1234",
        "cwe":123,
        "status":"need to recheck",
        "fix":"filter params",
        "technical": "<script>alert();</script>",
        "risks": "Database may be dropped",
        "references": "http://test.com",
        "intruder": "Internal",
        "type":"custom",
        "param" :"GET id=1",
        "services":       {"6e61925d-891e-4009-8cda-c9b7d78efeeb":["0","0a8796a1-6cc8-4063-a09c-6fdff379cf4c"]	},
        "fields": {
            "nessus_id": {
              "type": "number",
              "val": 1337
            }
        }
    }
    """
    name = args['name']
    if name is None:
        name = current_issue['name']

    if name == '':
        return fail(['Name must not be empty!'])

    cvss = args['cvss']
    if cvss is None:
        cvss = current_issue['cvss']

    url_path = args['url_path']
    if url_path is None:
        url_path = current_issue['url_path']

    description = args['description']
    if description is None:
        description = current_issue['description']

    cve = args['cve']
    if cve is None:
        cve = current_issue['cve']

    cwe = args['cwe']
    if cwe is None:
        cwe = current_issue['cwe']

    status = args['status']
    if status is None:
        status = current_issue['status']

    fix = args['fix']
    if fix is None:
        fix = current_issue['fix']

    param = args['param']
    if param is None:
        param = current_issue['param']

    services = args['services']
    if services is None:
        services = json.loads(current_issue['services'])

    issue_type = args["type"]
    if issue_type == None:
        issue_type = current_issue['type']

    issue_technical = args["technical"]
    if issue_technical == None:
        issue_technical = current_issue['technical']

    issue_risks = args["risks"]
    if issue_risks == None:
        issue_risks = current_issue['risks']

    issue_references = args["references"]
    if issue_references == None:
        issue_references = current_issue['references']

    issue_intruder = args["intruder"]
    if issue_intruder == None:
        issue_intruder = current_issue['intruder']

    # check port_id variable
    for port_id in services:
        if not is_valid_uuid(port_id):
            return fail(['Invalid port UUID!'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(['Some ports are not in project!'])
        current_port = current_port[0]
        for hostname_id in services[port_id]:
            if hostname_id != "0":
                if not is_valid_uuid(hostname_id):
                    return fail(['Invalid hostname UUID!'])
                hostnames = db.select_hostname(hostname_id)
                if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                    return fail(['Invalid hostname UUID!'])

    db.update_issue(current_issue['id'], name, description, url_path, cvss,
                    services, status, cve, cwe, fix, issue_type, param,
                    issue_technical, issue_risks, issue_references, issue_intruder)

    # update fields

    add_fields_dict = {}
    old_fields = json.loads(current_issue['fields'])
    if args['fields'] != None:
        for field_name in args['fields']:
            field_type = args['fields'][field_name]['type']
            field_value = args['fields'][field_name]['val']
            if field_type in ["text", "number", "float", "boolean"]:
                # add text field
                try:
                    if field_type == "text":
                        type_func = str
                    elif field_type == "number":
                        type_func = int
                    elif field_type == "float":
                        type_func = float
                    elif field_type == "boolean":
                        type_func = lambda x: bool(int(x))
                    add_fields_dict[field_name] = {
                        'val': type_func(field_value),
                        'type': field_type
                    }
                except:
                    pass

        for field_name in old_fields:
            if old_fields[field_name]['type'] == 'file' and field_name not in add_fields_dict:
                add_fields_dict[field_name] = old_fields[field_name]
        if add_fields_dict:
            db.update_issue_fields(current_issue['id'], add_fields_dict)

    return {"status": "ok"}


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/delete', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_issue_access
def project_issue_delete(args, current_user=None, current_token=None, user_id='',
                         project_id=None, current_project=None, issue_id='', current_issue=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/5c16f0de-dd80-4ffc-952f-4ed3f3e7d657/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    db.delete_issue_safe(current_project['id'], current_issue['id'])

    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/poc/add', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_poc_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_issue_access
def project_issue_poc_add(args, current_user=None, current_token=None,
                          user_id='', project_id=None, current_project=None, issue_id='', current_issue=None
                          ):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/ef8d2e2d-1da8-422d-b112-8a1805c947a9/poc/add HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 297

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "description": "Screenshot of ...",
        "type": "text",
        "b64content": "UGVudGVzdCBDb2xsYWJvcmF0aW9uIEZyYW1ld29yaw==",
        "port_id": "6e61925d-891e-4009-8cda-c9b7d78efeeb",
        "hostname_id": "0a8796a1-6cc8-4063-a09c-6fdff379cf4c"
    }
    """
    poc_description = args['description']
    poc_type = args['type']
    try:
        poc_content = base64.b64decode(args['b64content'])
    except binascii.Error:
        return fail(["Can't decode Base64!"])
    if len(poc_content) > int(config['files']['poc_max_size']):
        return fail(["File too large!"])
    poc_port_id = args['port_id']
    poc_hostname_id = args['hostname_id']

    # check port_id and hostname_id
    if not (poc_port_id == '0' and poc_hostname_id == '0'):
        # check if port-host in issue
        if not db.check_hostname_port_in_issue(poc_hostname_id, poc_port_id,
                                               current_issue['id']):
            return fail(['Hostname-port id pair is not in this issue!'])

    poc_id = gen_uuid()
    poc_path = path.join('./static/files/poc/', poc_id)
    f = open(poc_path, 'wb')
    f.write(poc_content)
    f.close()

    poc_filename = poc_id + '.png' if poc_type == 'image' else poc_id + '.txt'

    if config['files']['poc_storage'] == 'database':
        remove(poc_path)
    elif config['files']['poc_storage'] == 'filesystem':
        poc_content = b''

    db.insert_new_poc(poc_port_id,
                      poc_description,
                      poc_type,
                      poc_filename,
                      current_issue['id'],
                      current_user['id'],
                      poc_hostname_id,
                      poc_id,
                      storage=config['files']['poc_storage'],
                      data=poc_content)

    return {"status": "ok", "poc_id": poc_id}


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/poc/<uuid:poc_id>/info', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_issue_access
@check_project_issue_poc
def project_issue_poc_info(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None, issue_id='', current_issue=None,
                           poc_id='', current_poc=None
                           ):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/ef8d2e2d-1da8-422d-b112-8a1805c947a9/poc/a40820cf-088e-40ab-a844-bb4ba10ff397/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    poc_obj = {
        'id': current_poc['id'],
        'description': current_poc['description'],
        'path': '/static/files/poc/' + current_poc['id'],
        'filename': current_poc['filename'],
        'port_id': current_poc['port_id'],
        'hostname_id': current_poc['hostname_id'],
        'priority': current_poc['priority'],
        'type': current_poc['type']
    }

    return poc_obj


@routes.route('/api/v1/project/<uuid:project_id>/issues/<uuid:issue_id>/poc/<uuid:poc_id>/delete', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_issue_access
@check_project_issue_poc
def project_issue_poc_delete(args, current_user=None, current_token=None,
                             user_id='', project_id=None, current_project=None, issue_id='', current_issue=None,
                             poc_id='', current_poc=None
                             ):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/ef8d2e2d-1da8-422d-b112-8a1805c947a9/poc/a40820cf-088e-40ab-a844-bb4ba10ff397/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    db.delete_poc(current_poc['id'])

    return {'status': 'ok'}


@routes.route('/api/v1/project/<uuid:project_id>/hostnames', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_hostnames_list(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/hostnames HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    hostnames = db.select_project_hostnames(current_project['id'])

    hostnames_arr = []

    for hostname in hostnames:
        hostname_obj = {
            'id': hostname['id'],
            'hostname': hostname['hostname'],
            'description': hostname['description'],
            'host': {}
        }
        host = db.select_project_host(current_project['id'], hostname['host_id'])[0]
        hostname_obj['host'] = {
            'id': host['id'],
            'ip': host['ip'],
            'description': host['comment'],
            'os': host['os']
        }
        hostnames_arr.append(hostname_obj)

    return {'hostnames': hostnames_arr}


@routes.route('/api/v1/project/<uuid:project_id>/hostname/add', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_hostname_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_new_hostname(args, current_user=None, current_token=None,
                         user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/hostname/add HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    hostname = str(args['hostname'])
    description = args['description']
    host_id = str(args['host_id'])
    try:
        email_validator.validate_email_domain_part(hostname)
    except email_validator.EmailNotValidError:
        return fail(['Invalid hostname!'])

    host = db.select_project_host(current_project['id'], host_id)

    if not host:
        return fail(['Invalid host UUID!'])

    current_host = host[0]

    current_hostname = db.select_ip_hostname(current_host['id'], hostname)
    if current_hostname:
        current_hostname = current_hostname[0]
        hostname_id = current_hostname['id']
        if description != '':
            db.update_hostname(current_hostname['id'], description)
    else:
        hostname_id = db.insert_hostname(current_host['id'],
                                         hostname,
                                         description,
                                         current_user['id'])

    return {'id': hostname_id}


@routes.route('/api/v1/rules', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(get_issue_rules_args, location='json')
@check_access_token
def get_issue_rules(args, current_user=None, current_token=None, user_id=''):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/hostname/add HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "user_id": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "team_id": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "rule_ids": ["aed4ce53-c90f-436b-9909-79a2abf7cdaf", "aed4ce53-c90f-436b-9909-79a2abf7cdaf", "aed4ce53-c90f-436b-9909-79a2abf7cdaf"]
    }
    """
    form_user_id = str(args['user_id'])
    form_team_id = str(args['team_id'])
    form_rule_ids = [str(x) for x in args['rule_ids']]

    user_teams = db.select_user_teams(current_user['id'])

    user_teams_dict = {x['id']: x['name'] for x in user_teams}

    if form_team_id != '':
        found = 0
        for team in user_teams:
            if team['id'] == form_team_id:
                found = 1
        if not found:
            return fail(['Invalid team UUID!'])

    issue_rules = []

    if form_user_id != '' and form_user_id != current_user['id']:
        return fail(['Invalid user UUID!'])

    if form_user_id != '':
        # only user_id search
        issue_rules = db.select_user_issue_rules(form_user_id)
    elif form_team_id != '':
        # only team_id search
        issue_rules = db.select_team_issue_rules(form_team_id)
    else:
        # all rules
        issue_rules = db.select_user_all_issue_rules(current_user['id'], current_user['email'])

    return_issue_rules = []

    if form_rule_ids:
        for current_rule in issue_rules:
            if current_rule['id'] in form_rule_ids:
                return_issue_rules.append(current_rule)
    else:
        return_issue_rules = issue_rules

    return {"result":
        [
            {
                'id': x['id'],
                'name': x['name'],
                'team_id': x['team_id'],
                'user_id': x['user_id'],
                'team_name': user_teams_dict[x['team_id']] if x['team_id'] else ''
            }
            for x in return_issue_rules
        ]
    }


@routes.route('/api/v1/project/<uuid:project_id>/issues/rules/use', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(use_issue_rules_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_rules_use(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/issues/ef8d2e2d-1da8-422d-b112-8a1805c947a9/issues/rules/use HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 64

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf",
        "rule_ids": [],
        "issue_ids": []
    }
    """

    issues_list = [str(x) for x in args['issue_ids']]
    rules_list = [str(x) for x in args['rule_ids']]

    updated_issues = []

    rules_objs = []

    # check rules access:
    rules_obj_list = db.check_user_issue_rules_access(rules_list, current_user['id'], current_user['email'])

    # check issues access
    issues_obj_list = db.check_project_issues(issues_list, current_project['id'])

    # 1 - search for issues

    # prepare rules

    for current_rule in rules_obj_list:
        current_rule['search_rules'] = json.loads(current_rule['search_rules'])
        current_rule['extract_vars'] = json.loads(current_rule['extract_vars'])
        current_rule['replace_rules'] = json.loads(current_rule['replace_rules'])

        # fix search rules
        for search_rule in current_rule['search_rules']:
            if search_rule['type'] == 'substring':
                search_rule['val'] = sql_to_regexp(search_rule['val'])

        # fix extract_vars
        for extract_rule in current_rule['extract_vars']:
            if extract_rule['type'] == 'substring':
                extract_rule['val'] = extract_to_regexp(extract_rule['val'])

        # fix replace_rules
        for replace_rule in current_rule['replace_rules']:
            if replace_rule['type'] == 'substring':
                replace_rule['search_filter'] = re.escape(replace_rule['search_filter'])
            elif replace_rule['type'] == 'template':
                pass  # Code moved to next block

        rules_objs.append(current_rule)

    for current_issue in issues_obj_list:
        issue_changed = False
        current_issue['fields'] = json.loads(current_issue['fields'])

        for current_rule in rules_objs:
            # 1 - Search rule
            found = False
            for search_rule in current_rule['search_rules']:
                field_name = search_rule['field_name']
                compare_str = ''
                if field_name == 'name':
                    compare_str = current_issue['name']
                elif field_name == 'description':
                    compare_str = current_issue['description']
                elif field_name == 'fix':
                    compare_str = current_issue['fix']
                elif field_name == 'url':
                    compare_str = current_issue['url_path']
                elif field_name == 'cvss':
                    compare_str = str(current_issue['cvss'])
                elif field_name == 'cve':
                    compare_str = current_issue['cve']
                elif field_name == 'cwe':
                    compare_str = str(current_issue['cwe'])
                elif field_name == 'status':
                    compare_str = current_issue['status']
                elif field_name == 'technical':
                    compare_str = current_issue['technical']
                elif field_name == 'risks':
                    compare_str = current_issue['risks']
                elif field_name == 'references':
                    compare_str = current_issue['references']
                elif field_name == 'intruder':
                    compare_str = current_issue['intruder']
                elif field_name == 'parameter':
                    compare_str = current_issue['param']
                elif field_name == 'criticality':
                    cvss = current_issue['cvss']
                    if cvss == 0:
                        compare_str = 'info'
                    elif cvss <= 3.9:
                        compare_str = 'low'
                    elif cvss <= 6.9:
                        compare_str = 'medium'
                    elif cvss <= 8.9:
                        compare_str = 'high'
                    else:
                        compare_str = 'critical'
                else:
                    # check for additional fields
                    new_name = field_name.strip('_\t\n\r')
                    for issue_field_name in current_issue['fields']:
                        if issue_field_name == new_name and current_issue['fields'][issue_field_name]['type'] != 'file':
                            compare_str = str(current_issue['fields'][issue_field_name]['val'])
                # check
                reg_exp = search_rule['val']
                try:
                    found = bool(run_function_timeout(
                        re.match, int(config['timeouts']['regexp_timeout']),
                        pattern=reg_exp,
                        string=compare_str
                    ))
                    # found = bool(re.match(reg_exp, compare_str))
                except Exception as e:
                    found = False

            # 2 - Extract rules
            if found:
                variables_dict = {}
                for extract_rule in current_rule['extract_vars']:
                    field_name = extract_rule['field_name']
                    compare_str = ''
                    if field_name == 'name':
                        compare_str = current_issue['name']
                    elif field_name == 'description':
                        compare_str = current_issue['description']
                    elif field_name == 'fix':
                        compare_str = current_issue['fix']
                    elif field_name == 'url':
                        compare_str = current_issue['url_path']
                    elif field_name == 'cvss':
                        compare_str = str(current_issue['cvss'])
                    elif field_name == 'cve':
                        compare_str = current_issue['cve']
                    elif field_name == 'cwe':
                        compare_str = str(current_issue['cwe'])
                    elif field_name == 'technical':
                        compare_str = current_issue['technical']
                    elif field_name == 'risks':
                        compare_str = current_issue['risks']
                    elif field_name == 'references':
                        compare_str = current_issue['references']
                    elif field_name == 'intruder':
                        compare_str = current_issue['intruder']
                    elif field_name == 'status':
                        compare_str = current_issue['status']
                    elif field_name == 'parameter':
                        compare_str = current_issue['param']
                    elif field_name == 'criticality':
                        cvss = current_issue['cvss']
                        if cvss == 0:
                            compare_str = 'info'
                        elif cvss <= 3.9:
                            compare_str = 'low'
                        elif cvss <= 6.9:
                            compare_str = 'medium'
                        elif cvss <= 8.9:
                            compare_str = 'high'
                        else:
                            compare_str = 'critical'
                    else:
                        # check for additional fields
                        new_name = field_name.strip('_')
                        for issue_field_name in current_issue['fields']:
                            if issue_field_name == new_name and current_issue['fields'][issue_field_name][
                                'type'] != 'file':
                                compare_str = str(current_issue['fields'][issue_field_name]['val'])

                    variable_value = ''
                    try:
                        search_result = run_function_timeout(
                            re.search, int(config['timeouts']['regexp_timeout']),
                            pattern=extract_rule['val'],
                            string=compare_str
                        )
                        # search_result = re.search(extract_rule['val'], compare_str)
                        variable_value = str(search_result.group(1))
                    except Exception as e:
                        pass
                    variables_dict[extract_rule['name']] = variable_value

                # 3 - replace rules
                for replace_rule in current_rule['replace_rules']:
                    if replace_rule['type'] != 'template':
                        # replace variables
                        env = SandboxedEnvironment()
                        replace_str = replace_rule["replace_string"]
                        template_obj = env.from_string(replace_str)
                        try:
                            replace_str = run_function_timeout(
                                template_obj.render, int(config['timeouts']['report_timeout']),
                                variables_dict,
                                jinja_env=SandboxedEnvironment(autoescape=True)
                            )
                            issue_changed = True
                        except Exception as e:
                            pass

                        field_name = replace_rule['field_name']
                        field_original_value = ''
                        found = False
                        special_var = False
                        if field_name in ['name', 'description', 'fix', 'url', 'cvss', 'cve', 'cwe', 'status',
                                          'technical'
                                          'risks', 'references', 'intruder']:
                            field_original_value = current_issue[field_name]
                            issue_changed = True
                            found = True
                        elif field_name == 'parameter':
                            field_name = 'param'
                            field_original_value = current_issue[field_name]
                            issue_changed = True
                            found = True
                        else:
                            # check for additional fields
                            new_name = field_name.strip('_')
                            for issue_field_name in current_issue['fields']:
                                if issue_field_name == new_name and current_issue['fields'][issue_field_name][
                                    'type'] != 'file':
                                    issue_changed = True
                                    found = True
                                    field_original_value = str(current_issue['fields'][issue_field_name]['val'])
                                    special_var = True

                        if found:
                            regexp = re.compile(replace_rule['search_filter'])

                            result_string = ''
                            try:
                                result_string = str(run_function_timeout(
                                    regexp.sub, int(config['timeouts']['regexp_timeout']),
                                    repl=lambda x: replace_str,
                                    string=field_original_value
                                ))
                                # result_string = str(regexp.sub(lambda x: replace_str, field_original_value))
                            except Exception as e:
                                pass

                            if special_var:
                                # additional field
                                field_type = current_issue['fields'][field_name.strip('_')]['type']
                                try:
                                    if field_type == 'text':
                                        current_issue['fields'][field_name.strip('_')]['val'] = str(result_string)
                                    elif field_type == 'float':
                                        current_issue['fields'][field_name.strip('_')]['val'] = float(result_string)
                                    elif field_type == 'number':
                                        current_issue['fields'][field_name.strip('_')]['val'] = int(result_string)
                                    elif field_type == 'boolean':
                                        current_issue['fields'][field_name.strip('_')]['val'] = bool(result_string)
                                    issue_changed = True
                                except Exception as e:
                                    pass
                            else:
                                try:
                                    if field_name == 'cvss':
                                        current_issue[field_name] = float(result_string)
                                    elif field_name == 'cwe':
                                        current_issue[field_name] = int(result_string)
                                    else:
                                        current_issue[field_name] = str(result_string)
                                    issue_changed = True
                                except Exception as e:
                                    pass
                    else:
                        current_template = db.check_user_issue_template_access(replace_rule['id'], current_user['id'],
                                                                               current_user['email'])[0]
                        current_template['variables'] = json.loads(current_template['variables'])
                        replace_rule['template_obj'] = current_template

                        for template_var_name in replace_rule['vars']:
                            var_value = replace_rule['vars'][template_var_name]
                            # replace variables
                            env = SandboxedEnvironment()
                            template_obj = env.from_string(var_value)

                            replace_str = var_value
                            try:
                                replace_str = run_function_timeout(
                                    template_obj.render, int(config['timeouts']['report_timeout']),
                                    variables_dict,
                                    jinja_env=SandboxedEnvironment(autoescape=True)
                                )
                                replace_rule['vars'][template_var_name] = replace_str
                                issue_changed = True
                            except Exception as e:
                                pass

                        # use template at issue
                        ##########################

                        # replace field variables

                        for field_name in current_template['variables']:
                            if field_name in replace_rule['vars']:
                                try:
                                    if current_template['variables'][field_name]["type"] == "boolean":
                                        current_template['variables'][field_name]["val"] = bool(
                                            replace_rule['vars'][field_name])
                                    elif current_template['variables'][field_name]["type"] == "number":
                                        current_template['variables'][field_name]["val"] = int(
                                            replace_rule['vars'][field_name])
                                    elif current_template['variables'][field_name]["type"] == "float":
                                        current_template['variables'][field_name]["val"] = float(
                                            replace_rule['vars'][field_name])
                                    elif current_template['variables'][field_name]["type"] == "text":
                                        current_template['variables'][field_name]["val"] = str(
                                            replace_rule['vars'][field_name])
                                    issue_changed = True
                                except Exception as e:
                                    pass
                        add_variables_dict = current_template['variables']

                        def replace_tpl_text(text: str):
                            for variable_name in add_variables_dict:
                                variable_type = add_variables_dict[variable_name]['type']
                                variable_value = add_variables_dict[variable_name]['val']
                                if variable_type == 'boolean':
                                    variable_value = int(variable_value)
                                text = text.replace('__' + variable_name + '__', str(variable_value))
                            return text

                        issue_name = replace_tpl_text(current_template['name'])
                        issue_description = replace_tpl_text(current_template['description'])
                        issue_url_path = replace_tpl_text(current_template['url_path'])
                        issue_cvss = current_template['cvss']
                        issue_cwe = current_template['cwe']
                        issue_cve = replace_tpl_text(current_template['cve'])
                        issue_status = replace_tpl_text(current_template['status'])
                        issue_type = replace_tpl_text(current_template['type'])
                        issue_fix = replace_tpl_text(current_template['fix'])
                        issue_param = replace_tpl_text(current_template['param'])
                        issue_technical = replace_tpl_text(current_template['technical'])
                        issue_risks = replace_tpl_text(current_template['risks'])
                        issue_references = replace_tpl_text(current_template['references'])
                        issue_intruder = replace_tpl_text(current_template['intruder'])

                        issue_fields = json.loads(current_template['fields'])

                        for field_name in issue_fields:
                            if issue_fields[field_name]['type'] == 'text':
                                issue_fields[field_name]['val'] = replace_tpl_text(issue_fields[field_name]['val'])

                        current_issue = {
                            'id': current_issue['id'],
                            'name': issue_name,
                            'description': issue_description,
                            'url_path': issue_url_path,
                            'cvss': float(issue_cvss),
                            'cwe': int(issue_cwe),
                            'cve': issue_cve,
                            'user_id': current_issue['user_id'],
                            'services': current_issue['services'],
                            'status': issue_status,
                            'project_id': current_issue['project_id'],
                            'type': issue_type,
                            'fix': issue_fix,
                            'param': issue_param,
                            'technical': issue_technical,
                            'risks': issue_risks,
                            'references': issue_references,
                            'intruder': issue_intruder,
                            'fields': issue_fields
                        }
                # submit issue
                db.update_issue_with_fields(current_issue['id'], current_issue['name'], current_issue['description'],
                                            current_issue['url_path'], current_issue['cvss'],
                                            json.loads(current_issue['services']),
                                            current_issue['status'], current_issue['cve'], current_issue['cwe'],
                                            current_issue['fix'],
                                            current_issue['type'], current_issue['param'], current_issue['fields'],
                                            current_issue['technical'], current_issue['risks'],
                                            current_issue['references'],
                                            current_issue['intruder'])
                if current_issue['id'] not in updated_issues: updated_issues.append(current_issue['id'])
    return {'status': 'ok', 'updated_issues': len(updated_issues)}


@routes.route('/api/v1/project/<uuid:project_id>/tasks/list', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
def project_todo_list(args, current_user=None, current_token=None,
                      user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/tasks/list HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    tasks = db.select_project_tasks(current_project['id'])
    tasks_list = {
        'tasks': []
    }
    for task in tasks:
        task_obj = {
            "task_id": task["id"],
            "name": task["name"],
            "description": task["description"],
            "start_date": int(task["start_date"]),
            "finish_date": int(task["finish_date"]),
            "status": task["status"],
            "users": [],
            "teams": [],
            "services": json.loads(task["services"]),
            "criticality": task["criticality"]
        }

        for obj_user_id in json.loads(task['users']):
            selected_user = db.select_user_by_id(obj_user_id)[0]
            task_obj['users'].append(
                {
                    'id': obj_user_id,
                    'email': selected_user['email'],
                    'fname': selected_user['fname'],
                    'lname': selected_user['lname'],
                    'company': selected_user['company']
                }
            )

        # add teams

        for obj_team_id in json.loads(task['teams']):
            selected_team = db.select_team_by_id(obj_team_id)[0]
            task_obj['teams'].append(
                {
                    'id': obj_team_id,
                    'name': selected_team['name']
                }
            )
        tasks_list['tasks'].append(task_obj)
    return tasks_list


@routes.route('/api/v1/project/<uuid:project_id>/task/<uuid:task_id>/info', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_task_access
def project_todo_task_info(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None,
                           task_id=None, current_task=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/task/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/info HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    task_obj = {
        "task_id": current_task["id"],
        "name": current_task["name"],
        "description": current_task["description"],
        "start_date": int(current_task["start_date"]),
        "finish_date": int(current_task["finish_date"]),
        "status": current_task["status"],
        "users": [],
        "teams": [],
        "services": json.loads(current_task["services"]),
        "criticality": current_task["criticality"]
    }

    for obj_user_id in json.loads(current_task['users']):
        selected_user = db.select_user_by_id(obj_user_id)[0]
        task_obj['users'].append(
            {
                'id': obj_user_id,
                'email': selected_user['email'],
                'fname': selected_user['fname'],
                'lname': selected_user['lname'],
                'company': selected_user['company']
            }
        )

    # add teams

    for obj_team_id in json.loads(current_task['teams']):
        selected_team = db.select_team_by_id(obj_team_id)[0]
        task_obj['teams'].append(
            {
                'id': obj_team_id,
                'name': selected_team['name']
            }
        )
    return task_obj


@routes.route('/api/v1/project/<uuid:project_id>/task/<uuid:task_id>/delete', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(only_token_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_task_access
def project_todo_task_delete(args, current_user=None, current_token=None,
                             user_id='', project_id=None, current_project=None,
                             task_id=None, current_task=None):
    """
    POST /api/v1/project/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/task/53ade0ed-ea2d-4812-9676-8bdcf5b7412c/delete HTTP/1.1
    Host: 127.0.0.1:5000
    Content-Type: application/json
    Content-Length: 353

    {
        "access_token": "aed4ce53-c90f-436b-9909-79a2abf7cdaf"
    }
    """

    db.delete_task(current_task['id'])

    return {"status": "ok"}


@routes.route('/api/v1/project/<uuid:project_id>/task/<uuid:task_id>/edit', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(edit_task_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
@check_project_task_access
def project_todo_task_edit(args, current_user=None, current_token=None,
                           user_id='', project_id=None, current_project=None,
                           task_id=None, current_task=None):
    """
    POST /api/v1/project/1ffbce55-7836-40d2-9390-bffa2e9ddebe/task/c5ffc93a-611b-4db4-9d54-199fb3addc7d/edit HTTP/1.1
    Host: 126
    Content-Type: application/json
    Content-Length: 969

    {"access_token": "75180067-69c0-457c-b5e4-a9ccf6379d2e",
      "criticality": "info",
      "description": "ergergreg",
      "finish_date": 1700434800,
      "name": "c5ffc93a-611b-4db4-9d54-199fb3addc7d",
      "services": {
        "193b7014-d6ed-49e8-a506-2527016ec3cc": [
          "db9161f7-0a0e-49ca-994e-fd7e6786e1c9"
        ],
        "23f4940b-c227-4877-af93-1d646fc99b18": [
          "0d409bf5-3730-4b51-b85d-987c766d9596"
        ],
        "3eff5212-0f4c-418d-b9ab-aa07d4a133dc": [
          "0"
        ],
        "51715ce3-aad1-4cd7-95ab-ee114864438e": [
          "db9161f7-0a0e-49ca-994e-fd7e6786e1c9"
        ],
        "6e9637be-c86e-4031-892e-c5caaf56ac90": [
          "0"
        ],
        "72e033f5-dd0b-4914-a28c-24593fbae6c6": [
          "0"
        ],
        "d886c8c1-da64-4775-9977-ead54ac2403c": [
          "0"
        ]
      },
      "start_date": 1697839200,
      "status": "review",
      "teams": [ "17801c0a-1086-4846-8129-6e6e266a7462"
      ],
      "users": [ "82deea3b-2df8-4dd4-a9f4-7be0e1290c95"
      ]
    }
    """

    task_name = current_task['name']
    task_description = current_task['description']
    task_start_date = current_task['start_date']
    task_finish_date = current_task['finish_date']
    task_criticality = current_task['criticality']
    task_status = current_task['status']
    task_services = json.loads(current_task['services'])
    task_users = json.loads(current_task['users'])
    task_teams = json.loads(current_task['teams'])

    if args["name"] is not None and args["name"]:
        task_name = str(args["name"])
    if args["description"] is not None:
        task_description = str(args["description"])
    if args["start_date"] is not None:
        task_start_date = int(args["start_date"])
    if args["finish_date"] is not None:
        task_finish_date = int(args["finish_date"])
    if args["status"] is not None:
        task_status = str(args["status"])
    if args["criticality"] is not None:
        task_criticality = str(args["criticality"])

    # users
    if "users" in args:
        new_users_list = []
        for user_id in args["users"]:
            if db.check_user_project_access(current_project['id'], str(user_id)):
                new_users_list.append(str(user_id))
        task_users = new_users_list

    # teams
    if "teams" in args:
        new_teams_list = []
        project_team_ids = json.loads(current_project['teams'])
        for team_id in args["teams"]:
            if str(team_id) in project_team_ids:
                new_teams_list.append(str(team_id))
        task_teams = new_teams_list

    # services
    if args["services"]:
        # check port_id variable
        for port_id in args["services"]:
            if not is_valid_uuid(port_id):
                return fail(['Invalid port UUID!'])
            current_port = db.select_project_port(current_project['id'], port_id)
            if not current_port:
                return fail(['Some ports are not in project!'])
            current_port = current_port[0]
            for hostname_id in args["services"][port_id]:
                if hostname_id != "0":
                    if not is_valid_uuid(hostname_id):
                        return fail(['Invalid hostname UUID!'])
                    hostnames = db.select_hostname(hostname_id)
                    if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                        return fail(['Invalid hostname UUID!'])
        task_services = args["services"]

    db.update_task(
        task_name, task_description, task_criticality, task_teams, task_users, task_status,
        task_start_date, task_finish_date, task_services, current_task['id']
    )

    return {"status": "ok"}


@routes.route('/api/v1/project/<uuid:project_id>/task/new', methods=['POST'])
@requires_authorization
@csrf.exempt
@parser.use_args(new_task_args, location='json')
@check_access_token
@check_project_access
@check_project_archived
def project_todo_task_new(args, current_user=None, current_token=None,
                          user_id='', project_id=None, current_project=None):
    """
    POST /api/v1/project/1ffbce55-7836-40d2-9390-bffa2e9ddebe/task/new HTTP/1.1
    Host: 126
    Content-Type: application/json
    Content-Length: 933

    {"access_token": "75180067-69c0-457c-b5e4-a9ccf6379d2e",
      "criticality": "info",
      "description": "yyyyyy",
      "finish_date": 1700434800,
      "name": "wfwef",
      "services": {
        "193b7014-d6ed-49e8-a506-2527016ec3cc": [
          "db9161f7-0a0e-49ca-994e-fd7e6786e1c9"
        ],
        "23f4940b-c227-4877-af93-1d646fc99b18": [
          "0d409bf5-3730-4b51-b85d-987c766d9596"
        ],
        "3eff5212-0f4c-418d-b9ab-aa07d4a133dc": [
          "0"
        ],
        "51715ce3-aad1-4cd7-95ab-ee114864438e": [
          "db9161f7-0a0e-49ca-994e-fd7e6786e1c9"
        ],
        "6e9637be-c86e-4031-892e-c5caaf56ac90": [
          "0"
        ],
        "72e033f5-dd0b-4914-a28c-24593fbae6c6": [
          "0"
        ],
        "d886c8c1-da64-4775-9977-ead54ac2403c": [
          "0"
        ]
      },
      "start_date": 1697839200,
      "status": "todo",
      "teams": [ "17801c0a-1086-4846-8129-6e6e266a7462"
      ],
      "users": [ "82deea3b-2df8-4dd4-a9f4-7be0e1290c95"
      ]
    }
    """

    task_name = args['name']
    if not task_name:
        return fail(['Name must not be empty!'])
    task_description = args['description']
    task_start_date = args['start_date']
    task_finish_date = args['finish_date']
    task_criticality = args['criticality']
    task_status = args['status']
    task_services = args['services']
    task_users = args['users']
    task_teams = args['teams']

    # users
    new_users_list = []
    for user_id in task_users:
        if db.check_user_project_access(current_project['id'], str(user_id)):
            new_users_list.append(str(user_id))
    task_users = new_users_list

    # teams
    new_teams_list = []
    project_team_ids = json.loads(current_project['teams'])
    for team_id in task_teams:
        if str(team_id) in project_team_ids:
            new_teams_list.append(str(team_id))
    task_teams = new_teams_list

    # services

    # check port_id variable
    for port_id in task_services:
        if not is_valid_uuid(port_id):
            return fail(['Invalid port UUID!'])
        current_port = db.select_project_port(current_project['id'], port_id)
        if not current_port:
            return fail(['Some ports are not in project!'])
        current_port = current_port[0]
        for hostname_id in task_services[port_id]:
            if hostname_id != "0":
                if not is_valid_uuid(hostname_id):
                    return fail(['Invalid hostname UUID!'])
                hostnames = db.select_hostname(hostname_id)
                if not hostnames or hostnames[0]['host_id'] != current_port['host_id']:
                    return fail(['Invalid hostname UUID!'])

    task_id = db.insert_new_task(task_name, task_description, task_criticality, task_teams,
                                 task_users, task_status, task_start_date, task_finish_date, current_project['id'],
                                 task_services)

    return {"task_id": task_id}


### Process each module

modules_path = path.join("routes", "ui", "tools_addons", "import_plugins")
search_path = path.join(modules_path, "*")
modules = [path.basename(d) for d in glob.glob(search_path) if os.path.isdir(d)]

for module_name in modules:
    path_to_module = path.join(modules_path, module_name)
    path_to_python = path.join(path_to_module, "plugin.py")
    spec = importlib.util.spec_from_file_location("import_plugin", path_to_python)
    import_plugin = importlib.util.module_from_spec(spec)
    sys.modules["import_plugin"] = import_plugin
    spec.loader.exec_module(import_plugin)

    # tmp_vars
    route_name = import_plugin.route_name
    route_endpoint = "/api/v1/project/<uuid:project_id>/tool/{}/".format(route_name)
    tools_description = import_plugin.tools_description
    ToolArguments = import_plugin.ToolArguments
    process_request = import_plugin.process_request
    input_param_names = [x for x in ToolArguments.__dict__ if not x.startswith("_")]


    def create_view_func(func, import_plugin, path_to_module):
        @requires_authorization
        @csrf.exempt
        @check_access_token
        @check_project_access
        @check_project_archived
        def view_func(project_id, current_token, current_project, current_user):
            function_result = func(project_id, current_token, current_project, current_user, import_plugin,
                                   path_to_module)
            return function_result

        return view_func


    def import_plugin_form(project_id, current_token, current_project, current_user, import_plugin, path_to_module):
        # plugin data
        ToolArguments = import_plugin.ToolArguments
        process_request = import_plugin.process_request

        # change file arguments to string base64
        input_param_names = [x for x in ToolArguments.__dict__ if not x.startswith("_")]
        input_dict = {}
        for input_name in input_param_names:
            input_obj = getattr(ToolArguments, input_name)
            class_name = input_obj.field_class
            if class_name == wtforms.fields.simple.MultipleFileField or \
                    'is_file' in input_obj.kwargs['_meta'] and input_obj.kwargs['_meta']['is_file']:
                input_obj.field_class = wtforms.fields.simple.StringField
                input_obj.kwargs['_meta']['is_file'] = True
            else:
                input_obj.kwargs['_meta']['is_file'] = False
        # check request
        form = ToolArguments(meta={'csrf': False})
        form.validate()
        errors = []
        if form.errors:
            for field in form.errors:
                for error in form.errors[field]:
                    errors.append(error)

        if not errors:
            # process input parameters
            input_param_names = [x for x in ToolArguments.__dict__ if not x.startswith("_")]
            input_dict = {}
            for input_name in input_param_names:
                input_obj = getattr(form, input_name)
                class_name = input_obj.__class__
                if class_name in [wtforms.fields.simple.BooleanField,
                                  wtforms.fields.numeric.IntegerField,
                                  wtforms.fields.simple.StringField]:
                    if input_obj.meta["is_file"]:
                        input_dict[input_name] = []
                        try:
                            decoded_data = base64.b64decode(input_obj.data)
                            if decoded_data:
                                input_dict[input_name].append(decoded_data)
                        except Exception as e:
                            errors.append("Wrong base64 for file {}!".format(input_name))
                    else:
                        input_dict[input_name] = input_obj.data
        if not errors:
            try:
                error_str = process_request(current_user, current_project, db, input_dict, config)
            except OverflowError as e:
                error_str = "Unhandled python exception in plugin!"
                logging.error("Error with {} plugin: {}".format(import_plugin.route_name, e))
            if error_str:
                errors.append(error_str)
        return {"errors": errors}


    routes.add_url_rule(rule=route_endpoint,
                        endpoint=route_name + "_api",
                        view_func=create_view_func(import_plugin_form, import_plugin, path_to_module),
                        methods=["POST"])
