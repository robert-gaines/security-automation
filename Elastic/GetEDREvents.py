#!/usr/bin/env python3

_AUTH_ = 'RWG' # 10192022


import requests
import random
import json

requests.packages.urllib3.disable_warnings()

def GetAlerts(addr,token):
    headers  = {
                    
               }
    url      = "https://{0}/rest/container".format(addr)
    req      = requests.post(url,headers=headers,verify=False,timeout=15)

def main():
    print("[*] ELASTIC EDR - Get ALerts")
    addr  = ""#input("[+] Enter the SOAR IP address-> ")
    token = ""#input("[+] Enter the API Token -> ")


if(__name__ == '__main__'):
    main()