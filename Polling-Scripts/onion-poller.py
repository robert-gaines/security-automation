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

def AddContainerArtifact(key,ctr_id,rule,severity,source_address,source_port,destination_address,destination_port,start_time,message,secondary_message,tags):
    headers = {
                'ph-auth-token':key
              }
    url      = "https://{soar}:9999/rest/artifact"
    payload  = {}
    payload['name']         = rule
    payload['label']        = 'Event'
    payload['type']         = 'Detection'
    payload['severity']     = severity
    payload['container_id'] = ctr_id
    payload['cef'] = {
                       "destinationAddress": destination_address,
                       "destinationPort": destination_port,
                       "sourceAddress": source_address,
                       "sourcePort": source_port,
                       'startTime' : start_time,
                       'message': message,
                       'msg':secondary_message,
                     }
    payload['tags'] = tags
    payload = json.dumps(payload)
    req     = requests.post(url=url,headers=headers,data=payload,timeout=15,verify=False)

def main():
    headers = {
                'Content-Type':'application/json'
              }
    event_query_critical = json.dumps({
                            "query": {
                                        "bool": {
                                                    "must": [
                                                                {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}
                                                              ],
                                                    "filter": {
                                                                "terms": {
                                                                            "event.severity": [4]
                                                                         }
                                                              }
                                                }
                                      }
                            })
    event_query_high = json.dumps({
                            "query": {
                                        "bool": {
                                                    "must": [
                                                                {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}
                                                              ],
                                                    "filter": {
                                                                "terms": {
                                                                            "event.severity": [3]
                                                                         }
                                                              }
                                                }
                                      }
                            })
    event_query_medium = json.dumps({
                            "query": {
                                        "bool": {
                                                    "must": [
                                                                {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}
                                                              ],
                                                    "filter": {
                                                                "terms": {
                                                                            "event.severity": [2]
                                                                         }
                                                              }
                                                }
                                      }
                            })
    event_queries = [event_query_critical,event_query_high,event_query_medium]
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
    url = "https://{addr}:9200/_search"
    for query in event_queries:
        event_req        = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=query,verify=False)
        event_response   = event_req.json()
        if(event_response):
            hits             = event_response['hits']
            hits             = hits['hits']
            for hit in hits:
                source = hit['_source']
                source_port      = source['source']['port']
                source_addr      = source['source']['ip']
                destination_port = source['destination']['port']
                destination_addr = source['destination']['ip']
                rule             = source['rule']['name']
                rule_id          = source['rule']['uuid']
                category         = source['rule']['category']
                alert_message    = source['message']
                net_msg          = source['network']
                timestamp        = source['@timestamp']
                severity         = source['event']['severity_label']
                tags             = source['tags']
                subject    = "[NIDS Alert] {0}".format(rule)
                message   = "Triggered Rule:         {0} \n".format(rule)
                message   += "Category:               {0} \n".format(category)
                message   += "Rule ID:                {0} \n".format(rule_id)
                message   += "Severity:               {0} \n".format(severity)
                message   += "Time:                   {0} \n".format(timestamp)
                message   += "Source IP:              {0} \n".format(source_addr)
                message   += "Source Port:            {0} \n".format(source_port)
                message   += "Destination IP:         {0} \n".format(destination_addr)
                message   += "Destination Port:       {0} \n\n".format(destination_port)
                message   += "Decoded Network Data:   {0} \n\n".format(net_msg)
                message   += "Event Message:          {0} \n\n".format(alert_message)
                enhanced_message = 'Subject: {0}\n\n{1}'.format(subject,message)
                smtpObj.sendmail(sender,recipient,enhanced_message)
                try:
                    ctr_id = CreateContainer(key,"[NIDS] Alert: {0}".format(rule),"Network Intrusion Detection System Alert")
                    if(ctr_id is not None):
                        AddContainerArtifact(key,ctr_id,rule,severity,source_addr,source_port,destination_addr,destination_port,timestamp,alert_message,net_msg,tags)
                except Exception as e:
                    pass

if(__name__ == '__main__'):
    main()

    