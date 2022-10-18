######################## Base Args ########################
ARG BASE_REGISTRY=docker.io
ARG BASE_IMAGE=zarguell/python39
ARG BASE_TAG=latest

FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

RUN mkdir /pcf

ADD . /pcf

WORKDIR /pcf

RUN pip install -r requirements_unix.txt

ENTRYPOINT pip install -r requirements_unix.txt; if [ ! -e "./configuration/database.sqlite3" ]; then echo 'DELETE_ALL' | python new_initiation.py; fi && python run.py
