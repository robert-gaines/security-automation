#!/usr/bin/env python3

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth 
import requests
import urllib3
import smtplib
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    #
    sender     = ""
    recipient  = ""
    smtpServer = ''
    smtpPort   = 25
    #
    smtpObj = smtplib.SMTP(smtpServer,smtpPort)
    #
    url = "https://{addr}:9200/_search"
    event_req        = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=event_query,verify=False)
    event_response   = event_req.json()
    malware_req      = requests.post(headers=headers,url=url,auth = HTTPBasicAuth(username, passwd),data=malware_query,verify=False)
    malware_response = event_req.json()
    hits             = malware_response['hits']
    message_count = 0
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

    