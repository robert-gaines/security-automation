#!/usr/bin/env python3

_AUTH_ = 'RWG'

import requests

requests.packages.urllib3.disable_warnings()

def GetSystemInfo(addr,token):
    headers  = {
                    "ph-auth-token": token
               }
    url      = "https://{0}/rest/system_info".format(addr)
    req      = requests.get(url,headers=headers,verify=False,timeout=3)
    print(req.status_code)
    print(req.content)

def main():
    print("[*] Splunk Phantom SOAR - Get System Info ")
    addr  = input("[+] Enter the SOAR IP address-> ")
    token = input("[+] Enter the API Token -> ")
    GetSystemInfo(addr,token)

if(__name__ == '__main__'):
    main()
