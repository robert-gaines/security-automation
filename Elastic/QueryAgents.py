#!/usr/bin/env python3

from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def QueryAgents(username,password,query):
    headers = {
                'Content-Type':'application/json'
              }
    payload = {
                "query": "{0}".format(query)
              }
    req = requests.get("https://10.128.10.45:9200/api/_eql/search",headers=headers,data=payload, auth=(username,password), verify=False)
    print(req.status_code,req.content)

def main():
    username = ""
    password = ""
    query    = "process where process.name == \"regsvr32.exe\""
    QueryAgents(username,password,query)

main()
