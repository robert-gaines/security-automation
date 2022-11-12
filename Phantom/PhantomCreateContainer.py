#!/usr/bin/env python3

_AUTH_ = 'RWG'

import requests
import random
import json

requests.packages.urllib3.disable_warnings()

def CreateContainer(addr,token):
    headers  = {
                    "ph-auth-token": token
               }
    data     = {
                    "data":"Test Data",
                    "description":"Test Description",
                    "label":"events",
                    "name":"Test Container",
                    "sensitivity":"green",
                    "severity":"Low",
                    #"container_type":"case"
               }
    data = json.dumps(data)   ; print(data)
    url      = "https://{0}/rest/container".format(addr)
    req      = requests.post(url,headers=headers,data=data,verify=False,timeout=15)
    print(req.status_code)
    print(req.content)

def main():
    print("[*] Splunk Phantom SOAR - Create Container ")
    addr  = input("[+] Enter the SOAR IP address-> ")
    token = input("[+] Enter the API Token -> ")
    CreateContainer(addr,token)

if(__name__ == '__main__'):
    main()