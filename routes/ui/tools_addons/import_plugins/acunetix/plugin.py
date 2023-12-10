######## Imports #########
import ipaddress
import json
import logging
import urllib.parse
import socket

from IPy import IP

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import MultipleFileField, StringField, BooleanField
from wtforms.validators import *
from system.db import Database

######## Description #############
route_name = "acunetix"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/RQdpBTM/acunetix.png",
        "Official name": "Acunetix",
        "Short name": "acunetix",
        "Description": "Lets you manage security risks associated with your web presence. It detects an extensive range of web vulnerabilities and helps eliminate them.",
        "URL": "https://www.acunetix.com/",
        "Plugin author": "@drakylar"
    }
]


####### Input arguments ########
# FlaskWTF forms https://flask-wtf.readthedocs.io/en/1.2.x/

class ToolArguments(FlaskForm):
    files = MultipleFileField(
        label='files',
        description='.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )

    host = StringField(
        label='host',
        description='Host IP',
        default='',
        validators=[],
        _meta={"display_row": 1, "display_column": 2}
    )

    auto_resolve = BooleanField(label='auto_resolve',
                                  description="or automatic resolve ip from PCF server",
                                  default=False,
                                  validators=[],
                                  _meta={"display_row": 2, "display_column": 2})


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)
    # xml files
    for bin_file_data in input_dict['files']:
        try:
            scan_result = BeautifulSoup(bin_file_data.decode('charmap'), "html.parser").scangroup.scan
            start_url = scan_result.starturl.contents[0]
            parsed_url = urllib.parse.urlparse(start_url)
            protocol = parsed_url.scheme
            hostname = parsed_url.hostname
            if hostname is None:
                hostname = parsed_url.path
            port = parsed_url.port
            os_descr = scan_result.os.contents[0]
            port_banner = scan_result.banner.contents[0]
            web_banner = scan_result.webserver.contents[0]
            port_description = 'Banner: {} Web: {}'.format(port_banner,
                                                           web_banner)
            host_description = 'OS: {}'.format(os_descr)
            is_tcp = 1
            if not port:
                port = 80
                if protocol == 'https':
                    port = 443
            try:
                IP(hostname)
                host = hostname
                hostname = ''
            except:
                if input_dict['host']:
                    IP(input_dict['host'])
                    host = input_dict['host']
                elif input_dict['auto_resolve'] == 1:
                    host = socket.gethostbyname(hostname)
                else:
                    return 'ip not resolved!'

            # add host
            host_id = db.select_project_host_by_ip(current_project['id'], host)
            if not host_id:
                host_id = db.insert_host(current_project['id'],
                                         host,
                                         current_user['id'],
                                         host_description)
            else:
                host_id = host_id[0]['id']
                db.update_host_description(host_id, host_description)

            # add hostname
            hostname_id = ''
            if hostname and hostname != host:
                hostname_id = db.select_ip_hostname(host_id,
                                                    hostname)
                if not hostname_id:
                    hostname_id = db.insert_hostname(host_id,
                                                     hostname,
                                                     'Added from Acunetix scan',
                                                     current_user['id'])
                else:
                    hostname_id = hostname_id[0]['id']

            # add port
            port_id = db.select_ip_port(host_id, port, is_tcp)
            if not port_id:
                port_id = db.insert_host_port(host_id,
                                              port,
                                              is_tcp,
                                              protocol,
                                              port_description,
                                              current_user['id'],
                                              current_project['id'])
            else:
                port_id = port_id[0]['id']
                db.update_port_proto_description(port_id, protocol,
                                                 port_description)
            issues = scan_result.reportitems.findAll("reportitem")

            for issue in issues:
                issue_name = issue.contents[1].contents[0]
                module_name = issue.modulename.contents[0]
                uri = issue.affects.contents[0]
                request_params = issue.parameter.contents[0]
                impact = issue.impact.contents[0]
                issue_description = issue.description.contents[0] \
                    .replace('<br/>', '\n') \
                    .replace('<strong>', '') \
                    .replace('</strong>', '') \
                    .replace('<code>', '\n') \
                    .replace('</code>', '\n') \
                    .replace('<pre>', '') \
                    .replace('</pre>', '')
                recomendations = issue.recommendation.contents[0]
                issue_request = issue.technicaldetails.request.contents[0]
                references_arr = issue.references.findAll("reference")
                references_str = ''
                for reference_obj in references_arr:
                    database = reference_obj.database.contents[0]
                    ref_url = reference_obj.url.contents[0]
                    references_str += '- {}: {}'.format(database, ref_url).strip(' \t\n\r') + '\n'

                references_str = references_str.strip(' \t\n\r')

                cwe = 0
                if issue.cwe:
                    cwe = int(issue.cwe['id'].replace('CWE-', ''))
                cvss = float(issue.cvss.score.contents[0])
                # TODO: check CVE field

                full_info = issue_description

                services = {port_id: ['0']}
                if hostname_id:
                    services = {port_id: ['0', hostname_id]}

                db.insert_new_issue(issue_name,
                                    full_info,
                                    uri,
                                    cvss,
                                    current_user['id'], services,
                                    'need to check',
                                    current_project['id'],
                                    cve=0,
                                    cwe=cwe,
                                    issue_type='web',
                                    fix=recomendations,
                                    param=request_params,
                                    technical=issue_request,
                                    references=references_str,
                                    fields={
                                        'acunetix_module':
                                            {'type': 'text',
                                             'val': module_name
                                             }
                                    },
                                    risks=impact
                                    )

        except Exception as e:
            logging.error("Error during parsing report: {}".format(e))
            return "Error during parsing Acunetix report!"

    return ""
