from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth
import pandas as pd
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def GetContainers(key):
    headers = {
                'ph-auth-token':key
              }
    page_index = 1
    url        = "https://<soar-addr>:9999/rest/container"
    req        = requests.get(headers=headers,url=url,timeout=15,verify=False)
    events     = []
    if(req.status_code == 200):
        status_code = 200
        data = req.json()['data']
        for entry in data:
            events.append(entry)
        while(status_code == 200):
            url         = "https://<soar-addr>:9999/rest/container?page={0}".format(page_index)
            req         = requests.get(headers=headers,url=url,timeout=15,verify=False)
            status_code = req.status_code
            if(status_code == 200 and req.json()['data']):
                data = req.json()['data']
                for entry in data:
                    events.append(entry)
                page_index += 1
            else:
                return events

    

def main():
    key    = ""
    events = GetContainers(key)
    df     = pd.DataFrame(events).to_excel("soar_events.xlsx",sheet_name='SOAR Events',index=False)

if(__name__ == '__main__'):
    main()
    
