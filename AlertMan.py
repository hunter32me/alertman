#!/usr/bin/env python3

from asyncore import file_wrapper
from distutils import filelist
import shutil
from this import d, s
import requests
from urllib3.exceptions import InsecureRequestWarning
import glob
import time
import sys
import zipfile
import os
import random


def checkRequest(responseObj):
    code = responseObj.status_code
    if code == 200:
        return 200

    if 400 <= code <= 500:
        print(responseObj.json())
        time.sleep(5)
        return code
    return code

def input_bool(question, default=None):

    prompt = " [yn]"

    if default is not None:
        prompt = " [Yn]:" if default else " [yN]:"

    while True:
        val = input(question + prompt)
        val = val.lower()
        if val  == '' and default is not None:
            return default
        if val in ('y', 'n'):
            return val == 'y'
        print("Invalid response")

def input_int(question):
    while True:
        val = input(question + ": ")
        try:
            return int(val)
        except ValueError as e:
            print("Invalid response", e)

def testConnection(session, baseURI):
    testUri = "/_cat/indices?v&pretty"
    uri = baseURI + testUri
    response = session.get(uri, timeout=5)
    checkRequest(response)
    response.raise_for_status()
    
def GetAlerts(session, baseURI):
    uri = "/.siem-signals*/_search"
    payload = "{ \"query\": { \"bool\": { \"must\": [ { \"query_string\": { \"query\": \"kibana.alert.severity: critical\", \"analyze_wildcard\": true}}], \"filter\": [{\"range\": {\"@timestamp\": {\"format\": \"strict_date_optional_time\" ,\"gte\": \"now-5m\",\"lte\": \"now\"}}} ],\"should\": [],\"must_not\": []}},\"fields\": [\"event.id\",  \"kibana.alert.rule.name\",\"source.ip\",\"destination.ip\"],\"_source\": false}"
    url = baseURI + uri
    response = session.get(url, timeout=5, data=payload)
    checkRequest(response)
    print(response.content)



def config():
    """Return a baseURI and session"""

    s = requests.Session()
    s.headers={'Content-Type': 'application/json'}

    ipHost = ""
    port = 9200
    user = ""
    password = ""
    s.auth = (user, password)
    ignoreCertErrors = True
    s.verify = not ignoreCertErrors
    proto = "https"
    baseURI = proto + "://" + ipHost + ":" + str(port)
    return baseURI, s

def main():
    baseURI, session = config()
    testConnection(session, baseURI)
    GetAlerts(session,baseURI)

main()