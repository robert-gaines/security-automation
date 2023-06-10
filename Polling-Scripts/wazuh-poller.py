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
    url       = "https://{0}:9999/rest/container"
    payload   = json.dumps(container)
    ctr_id    = ""
    req = requests.post(headers=headers,url=url,data=payload,timeout=15,verify=False)
    if(req.status_code == 200):
        ctr_id = req.json()
        ctr_id = ctr_id['id']
        return ctr_id
    else:
        return None

def AddContainerArtifact(key,ctr_id,rule_desc,agent_name,agent_ip,data,timestamp,location,decoder):
    headers = {
                'ph-auth-token':key
              }
    url      = "https://{soar}:9999/rest/artifact"
    payload  = {}
    payload['name']         = rule_desc
    payload['label']        = 'Event'
    payload['type']         = 'Alert'
    payload['severity']     = 'High'
    payload['container_id'] = ctr_id
    payload['cef'] = {
                       "sourceAddress": agent_ip,
                       "sourceHostname":agent_name,
                       'startTime' : timestamp,
                       'message': data,
                       'msg':location
                     }
    payload = json.dumps(payload)
    req     = requests.post(url=url,headers=headers,data=payload,timeout=15,verify=False)

def main():
    headers = {
                'Content-Type':'application/json'
              }
    event_query_level_ten      = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 10}} ] } } })
    event_query_level_eleven   = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 11}} ] } } })
    event_query_level_twelve   = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 12}} ] } } })
    event_query_level_thirteen = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 13}} ] } } })
    event_query_level_fourteen = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 14}} ] } } })
    event_query_level_fifteen  = json.dumps( { "query": { "bool": { "must": [ {"range": { "@timestamp":{ "gte":"now-5m","lt":"now"  }}}, {"match": {"rule.level": 15}} ] } } })
    
    event_queries = [
                      event_query_level_ten,
                      event_query_level_eleven,
                      event_query_level_twelve,
                      event_query_level_thirteen,
                      event_query_level_fourteen,
                      event_query_level_fifteen
                    ]
    
    username = ''
    passwd   = ''
    key      =  ""
    #
    sender     = ""
    recipient  = ""
    smtpServer = ''
    smtpPort   = 25
    #
    smtpObj    = smtplib.SMTP(smtpServer,smtpPort)
    #
    url           = "https://{addr}:9200/_search"
    unique_events = []
    for query in event_queries:
        event_req        = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=query,verify=False)
        event_response   = event_req.json()
        if(event_response):
            hits             = event_response['hits']
            hits             = hits['hits']
            for hit in hits:
                source = hit['_source']
                agent_ip         = source['agent']['ip']
                agent_name       = source['agent']['name']
                data             = source['data']
                rule_desc        = source['rule']['description']
                decoder          = source['decoder']
                timestamp        = source['timestamp']
                location         = source['location']
                event_tuple      = (rule_desc,agent_name)
                if(event_tuple not in unique_events):
                    subject    = "[HIDS Alert] {0}".format(rule_desc)
                    message    = "HIDS Agent Name:                    {0} \n".format(agent_name)
                    message   += "HIDS Agent IP:                      {0} \n".format(agent_ip)
                    message   += "Triggered Rule Description:         {0} \n".format(rule_desc)
                    message   += "Data:                               {0} \n".format(data)
                    message   += "Decoder:                            {0} \n".format(decoder)
                    message   += "Log Source:                         {0} \n".format(location)
                    message   += "Event Time:                         {0} \n".format(timestamp)
                    enhanced_message = 'Subject: {0}\n\n{1}'.format(subject,message)
                    smtpObj.sendmail(sender,recipient,enhanced_message)
                    try:
                        ctr_id = CreateContainer(key,"[HIDS] Alert: {0}".format(rule_desc),"Host Intrusion Detection System Alert")
                        if(ctr_id is not None):
                            AddContainerArtifact(key,ctr_id,rule_desc,agent_name,agent_ip,data,timestamp,location,decoder)
                    except Exception as e:
                        print(e)
                        pass
                    unique_events.append(event_tuple)

if(__name__ == '__main__'):
    main()

    