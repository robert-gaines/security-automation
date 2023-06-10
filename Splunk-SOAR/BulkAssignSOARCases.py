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
    ctr_ids    = []
    page_index = 1
    url        = "https://<soar-addr>:9999/rest/container?page_index={0}".format(page_index)
    req        = requests.get(headers=headers,url=url,timeout=15,verify=False)
    if(req.status_code == 200):
        status_code = 200
        data = req.json()['data']
        for entry in data:
            ctr_id      = entry['id']
            status      = entry['status']
            if(ctr_id not in ctr_ids):
                AssignCase(key,ctr_id)
                ctr_ids.append(ctr_id)
        page_index += 1
        while(status_code == 200):
            url         = "https://<soar-addr>:9999/rest/container?page={0}".format(page_index)
            req         = requests.get(headers=headers,url=url,timeout=15,verify=False)
            status_code = req.status_code
            if(status_code == 200 and req.json()['data']):
                data = req.json()['data']
                for entry in data:
                    ctr_id      = entry['id']
                    status      = entry['status']
                    if(ctr_id not in ctr_ids):
                        AssignCase(key,ctr_id)
                        ctr_ids.append(ctr_id)
                page_index += 1
            else:
                return

def AssignCase(key,ctr_id):
    print("Splunk SOAR Bulk Assignment Script")
    headers  = {
                'ph-auth-token':key
               }
    url      = "https://<soar-addr>:9999/rest/container/{0}".format(ctr_id)
    payload  = {}
    payload['owner_id']     = ''
    payload = json.dumps(payload)
    req     = requests.post(url=url,headers=headers,data=payload,timeout=15,verify=False)
    print(req.json())

def main():
    key = ""
    GetContainers(key)

if(__name__ == '__main__'):
    main()
    
