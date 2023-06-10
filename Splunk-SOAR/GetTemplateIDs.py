from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth 
import requests
import urllib3
import smtplib
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def GetContainers(key):
    headers = {
                'ph-auth-token':key
              }
    url        = "https://<soar-addr>:9999/rest/workbook_template"
    req        = requests.get(headers=headers,url=url,timeout=15,verify=False)
    if(req.status_code == 200):
        status_code = 200
        data = req.json()['data']
        for item in data:
            print(item)
        print()

def main():
    key = ""
    GetContainers(key)

if(__name__ == '__main__'):
    main()
    
