from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth 
import requests
import urllib3
import smtplib
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def CreateContainer(key,source,description):
    headers = {
                'ph-auth-token':key
              }
    
    container = {
                    'name'        : source,
                    'description' : description
                }
    url       = "https://{soar}:9999/rest/container"
    payload   = json.dumps(container)
    ctr_id    = ""
    req = requests.post(headers=headers,url=url,data=payload,timeout=15,verify=False)
    if(req.status_code == 200):
        ctr_id = req.json()
        ctr_id = ctr_id['id']
        return ctr_id
    else:
        return None

def AddContainerArtifact(key,ctr_id,hostname,start_time,message,secondary_message,file_hash):
    headers = {
                'ph-auth-token':key
              }
    url      = "https://{soar}:9999/rest/artifact"
    payload  = {}
    payload['name']     = 'EDR Sensor Data'
    payload['label']    = 'Event'
    payload['type']     = 'Detection'
    payload['severity'] = "High"
    payload['container_id'] = ctr_id
    payload['cef'] = {
                       'sourceHostname':hostname,
                       'startTime' : start_time,
                       'message': message,
                       'msg':secondary_message,
                       'fileHash': file_hash
                     }
    payload['tags'] = ["EDR","Malware"]
    payload = json.dumps(payload)
    req     = requests.post(url=url,headers=headers,data=payload,timeout=15,verify=False)
    print(req.json())

def main():
    headers = {
                'Content-Type':'application/json'
              }
    malware_query = json.dumps({
                                "query": {
                                    "bool": {
                                        "must": [
                                            {"match": {"signal.rule.name": "Malware Prevention Alert"}},
                                            {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}
                                        ]
                                    }
                                }
                               })
    event_query = json.dumps({
                            "query": {
                                "bool": {
                                    "must": [
                                        {"match": {"signal.status": "open"}},
                                        {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}
                                    ]
                                }
                             }
                            })
    username = ''
    passwd   = ''
    key      =  ""
    #
    sender     = ""
    recipient  = ""
    smtpServer = ''
    smtpPort   = 25
    #
    smtpObj = smtplib.SMTP(smtpServer,smtpPort)
    #
    url = "https://{edr}:9200/_search"
    event_req        = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=event_query,verify=False)
    event_response   = event_req.json()
    malware_req      = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=malware_query,verify=False)
    malware_response = malware_req.json()
    if(malware_response):
        hits          = malware_response['hits']
        sub_hits      = hits['hits']
        for hit in sub_hits:
            source       = hit['_source']
            file_name    = source['file']
            ext          = str(file_name['Ext'])
            startTime    = file_name['created']
            file_hash    = file_name['hash']['sha256']
            malware_data = ""
            for entry in file_name.keys():
                malware_data += entry+':'+str(file_name[entry])+"\n"
            rule_name = source['kibana.alert.rule.name']
            try:
                hostname  = source['host']['hostname']
            except:
                hostname  = 'Hostname Not Available'
            eventtime        = source['@timestamp']
            rule_data        = source['kibana.alert.reason']
            artifact_message = rule_data
            subject    = "[EDR Alert] {0}:{1}".format(hostname,rule_name)
            message    = "Triggered Rule:  {0} \n".format(rule_name)
            message   += "Affected Host:   {0} \n".format(hostname)
            message   += "Event Time:      {0} \n".format(eventtime)
            message   += "Event Message:   {0} \n".format(rule_data)
            message   += "Malware Data: \n {0} \n".format(malware_data)
            enhanced_message = 'Subject: {0}\n\n{1}'.format(subject,message)
            smtpObj.sendmail(sender,recipient,enhanced_message)
            try:
                ctr_id = CreateContainer(key,"[EDR] Malware Alert","Malware Detection/Prevention Event")
                if(ctr_id is not None):
                    AddContainerArtifact(key,ctr_id,hostname,startTime,message,ext,file_hash)
            except Exception as e:
                pass
    if(event_response):
        hits     = event_response['hits']
        sub_hits = hits['hits']
        for hit in sub_hits:
            source = hit['_source']
            rule_name = source['kibana.alert.rule.name']
            try:
                hostname  = source['host']['hostname']
            except:
                hostname  = 'Hostname Not Available'
            eventtime  = source['@timestamp']
            rule_data  = source['kibana.alert.reason']
            subject    = "[EDR Alert] {0}:{1}".format(hostname,rule_name)
            message    = "Triggered Rule: {0} \n".format(rule_name)
            message   += "Affected Host:  {0} \n".format(hostname)
            message   += "Event Time:     {0} \n".format(eventtime)
            message   += "Event Message:  {0} ".format(rule_data)
            enhanced_message = 'Subject: {0}\n\n{1}'.format(subject,message)
            smtpObj.sendmail(sender,recipient,enhanced_message)

if(__name__ == '__main__'):
    main()

    