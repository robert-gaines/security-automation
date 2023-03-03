from requests.packages.urllib3.exceptions import InsecureRequestWarning
from base64 import b64encode
import xlsxwriter
import requests
import datetime
import getpass
import urllib3
import socket
import time
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def TimeStamp():
    var         = time.ctime()
    sans_colons = var.replace(":","_")
    sans_spaces = sans_colons.replace(" ","_")
    timestamp   = sans_spaces
    return timestamp

def GenFileName():
    file_name = "VulnerabilityRecord_"
    timestamp = TimeStamp()
    file_name += timestamp
    file_name += ".xlsx"
    return file_name

def LocateScan(scans,identity):
    for scan in scans:
        if(scan['id'] == identity):
            return scan
    return None

def CreateVulnRecord(nessus_host,access_key,secret_key):
    headers       = {'X-ApiKeys': 'accessKey={0}; secretKey={1}'.format(access_key,secret_key)}
    scans_url     = "https://{0}/scans".format(nessus_host)
    try:
        scans_req     = requests.get(headers=headers,url=scans_url,verify=False)
    except Exception as e:
        print("[!] Exception: {0}".format(e))
        time.sleep(1)
        sys.exit()
    if(scans_req.status_code == 200):
        print("[*] Successfully connected with the Nessus Server ")
        scans         = scans_req.json()['scans']
        proceed       = 'Y'
        subject_scans = []
        while(proceed != "n" and proceed != "N"):
            for scan in scans:
                scan_id   = scan['id']
                scan_name = scan['name']
                print(scan_id,scan_name)
            try:
                subject_scan_id  = int(input("[+] Enter ID of the scan -> "))
                subject_scan     = LocateScan(scans,subject_scan_id)
            except Exception as e:
                print("[!] Exception thrown: {0}".format(e))
                time.sleep(1)
                sys.exit()
            if(subject_scan is not None):
                print("[*] Located: {0}:{1} ".format(subject_scan['id'],subject_scan['name']))
                subject_scans.append(subject_scan)
            else:
                print("[!] Failed to locate scan ")
            proceed = input("[+] Continue adding scans? (y/n)")
        print("[*] Processing the following scans: ")
        for scan in subject_scans:
            print("[*] {0}:{1} ".format(scan['id'],scan['name']))
        print("[~] Creating the vulnerability record document...")
        #
        fileName          = GenFileName()
        workbook          = xlsxwriter.Workbook(fileName)
        header_format     = workbook.add_format({'bold': True, 'bg_color': 'cyan'})
        header_format.set_center_across()
        delim_format      = workbook.add_format({'bg_color': 'black'})
        low_risk_format   = workbook.add_format({'bg_color': 'green'})
        med_risk_format   = workbook.add_format({'bg_color': 'yellow'})
        high_risk_format  = workbook.add_format({'bg_color': 'red'})
        #
        acceptable_format = workbook.add_format({'bg_color': 'green'})
        req_attn_format   = workbook.add_format({'bg_color': 'yellow'})
        not_applicable    = workbook.add_format({'bg_color': 'gray'})
        #
        accepted_format  = workbook.add_format({'bg_color': 'lime'})
        mitigated_format = workbook.add_format({'bg_color': 'yellow'})
        repairing_format = workbook.add_format({'bg_color': 'cyan'})
        review_format    = workbook.add_format({'bg_color': 'magenta'})
        repaired_format  = workbook.add_format({'bg_color': 'green'})
        #
        for scan in subject_scans:
            scan_id    = scan['id']
            scan_name  = scan['name']
            sheet_name = str(scan_id)+'-'+scan_name
            if(len(sheet_name) >= 30):
                sheet_name = sheet_name[0:29]
            current_worksheet = workbook.add_worksheet(sheet_name)
            host_headers      = [
                                    'Asset Name',
                                    'IP Address',
                                    'Scan Date',
                                    'Status',
                                    'Rescan Date',
                                    'Status After Rescan',
                                    ' ',
                                    ' ',
                                    ' ',
                                    ' ',
                                    ' '
                                ]
            scan_headers      = [
                                    'Status',
                                    'Jira Ticket #',
                                    'Name',
                                    'CVE',
                                    'CVSS',
                                    'Risk',
                                    'Host',
                                    'Protocol',
                                    'Port',
                                    'Synopsis',
                                    'Notes'
                                ]
            chars             = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
            limit             = len(host_headers)
            current_iter      = 0
            alpha_iter        = 0
            col_index         = 1
            secondary_index   = 0
            col_hdr_index     = 0
            while(current_iter < limit-1):
                char_index = 0
                if(current_iter == limit):
                    break
                while(alpha_iter <= 25):
                    if(current_iter == limit):
                        break
                    if(current_iter > 25):
                        write_index = chars[secondary_index]+chars[alpha_iter]+str(col_index)
                        current_worksheet.write(write_index,host_headers[col_hdr_index],header_format)
                    if(current_iter <= 25):
                        write_index = chars[char_index]+str(col_index)
                        current_worksheet.write(write_index,host_headers[col_hdr_index],header_format)
                    current_iter += 1 ; char_index += 1 ; alpha_iter += 1 ; col_hdr_index += 1
                if(current_iter > 50):
                    secondary_index += 1
                char_index = 0
                alpha_iter = 0
            row_index = 2
            try:
                single_scan_url  = "https://{0}/scans/{1}".format(nessus_host,scan_id)
                single_scan_req  = requests.get(headers=headers,url=single_scan_url,verify=False)
                single_scan_data = single_scan_req.json()
                scan_finished    = datetime.datetime.fromtimestamp(single_scan_data['info']['scanner_end'])
                for host in single_scan_data['hosts']:
                    temp_entry_list  = []
                    host_name        = host['hostname']
                    host_addr        = ''
                    try:
                        host_addr = socket.gethostbyname(host_name)
                    except:
                        host_addr = ' '
                    temp_entry_list.append(host_name)
                    temp_entry_list.append(host_addr)
                    temp_entry_list.append(scan_finished)
                    current_iter      = 0
                    alpha_iter        = 0
                    secondary_index   = 0
                    limit             = len(temp_entry_list)
                    while(current_iter < limit-1):
                        char_index = 0
                        if(current_iter == limit):
                            break
                        while(alpha_iter <= 25):
                            if(current_iter == limit):
                                break
                            if(current_iter > 25):
                                write_index = chars[secondary_index]+chars[alpha_iter]+str(row_index)
                                write_value = str(temp_entry_list[current_iter])
                                current_worksheet.write(write_index,write_value)
                            if(current_iter <= 25):
                                write_index = chars[alpha_iter]+str(row_index)
                                write_value = str(temp_entry_list[current_iter])
                                current_worksheet.write(write_index,write_value)
                            current_iter += 1 ; char_index += 1 ; alpha_iter += 1
                        if(current_iter > 50):
                            secondary_index += 1
                        char_index = 0
                        alpha_iter = 0
                    current_iter   = 0
                    status_index  = 'D'+str(row_index)
                    rescan_index  = 'E'+str(row_index)
                    rescan_status = 'F'+str(row_index)
                    current_worksheet.data_validation(status_index,{'validate':'list','source':['Acceptable','Needs Attention','N/A']})
                    current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Acceptable"'.format(status_index),'format'      : acceptable_format})
                    current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Needs Attention"'.format(status_index),'format' : req_attn_format})
                    current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="N/A"'.format(status_index),'format'             : not_applicable})
                    #
                    current_worksheet.write(rescan_index,'')
                    #
                    current_worksheet.conditional_format(rescan_status, {'type': 'formula','criteria': '=${0}="Acceptable"'.format(rescan_status),'format'             : acceptable_format})
                    current_worksheet.conditional_format(rescan_status, {'type': 'formula','criteria': '=${0}="Needs Attention"'.format(rescan_status),'format'        : req_attn_format})
                    current_worksheet.conditional_format(rescan_status, {'type': 'formula','criteria': '=${0}="N/A"'.format(rescan_status),'format'                    : not_applicable})
                    current_worksheet.data_validation(rescan_status,{'validate':'list','source':['Acceptable','Needs Attention','N/A']})
                    row_index += 1
            except Exception as e:
                print("[!] Error Processing: {0}".format(scan_id))
                print("[!] Exception: {0}".format(e))
                pass
            limit             = len(host_headers)
            current_iter      = 0
            alpha_iter        = 0
            col_index         = row_index
            secondary_index   = 0
            col_hdr_index     = 0
            while(current_iter < limit-1):
                char_index = 0
                if(current_iter == limit):
                    break
                while(alpha_iter <= 25):
                    if(current_iter == limit):
                        break
                    if(current_iter > 25):
                        write_index = chars[secondary_index]+chars[alpha_iter]+str(col_index)
                        current_worksheet.write(write_index,host_headers[col_hdr_index],header_format)
                    if(current_iter <= 25):
                        write_index = chars[char_index]+str(col_index)
                        current_worksheet.write(write_index,'',delim_format)
                    current_iter += 1 ; char_index += 1 ; alpha_iter += 1 ; col_hdr_index += 1
                if(current_iter > 50):
                    secondary_index += 1
                char_index = 0
                alpha_iter = 0
            row_index += 1
            scan_headers      = [
                                    'Status',
                                    'Jira Ticket #',
                                    'Name',
                                    'CVE',
                                    'CVSS',
                                    'Risk',
                                    'Host',
                                    'Protocol',
                                    'Port',
                                    'Synopsis',
                                    'Notes'
                                ]
            chars             = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
            limit             = len(scan_headers)
            current_iter      = 0
            alpha_iter        = 0
            col_index         = row_index
            secondary_index   = 0
            col_hdr_index     = 0
            while(current_iter < limit-1):
                char_index = 0
                if(current_iter == limit):
                    break
                while(alpha_iter <= 25):
                    if(current_iter == limit):
                        break
                    if(current_iter > 25):
                        write_index = chars[secondary_index]+chars[alpha_iter]+str(col_index)
                        current_worksheet.write(write_index,scan_headers[col_hdr_index],header_format)
                    if(current_iter <= 25):
                        write_index = chars[char_index]+str(col_index)
                        current_worksheet.write(write_index,scan_headers[col_hdr_index],header_format)
                    current_iter += 1 ; char_index += 1 ; alpha_iter += 1 ; col_hdr_index += 1
                if(current_iter > 50):
                    secondary_index += 1
                char_index = 0
                alpha_iter = 0
            row_index += 1
            for entry in single_scan_data['hosts']:
                host_id   = entry['host_id']
                host_name = entry['hostname']
                host_detail_url = "https://{0}/scans/{1}/hosts/{2}".format(nessus_host,scan_id,host_id)
                host_detail_req = requests.get(headers=headers,url=host_detail_url,verify=False)
                host_details    = host_detail_req.json()
                vulnerabilities = host_details['vulnerabilities']
                for entry in vulnerabilities:
                    host_id           = host_id
                    host_name         = host_name
                    plugin_id         = entry['plugin_id']
                    plugin_name       = entry['plugin_name']
                    cve               = ''
                    cvss              = entry['score']
                    risk              = ''
                    if(cvss != None and cvss != ''):
                        cvss = float(cvss)
                        if(cvss > 0 and cvss <= 3.9):
                            risk = 'Low'
                        if(cvss >= 4.0 and cvss <= 6.9):
                            risk = 'Medium'
                        if(cvss > 7.0 and cvss <= 10.0):
                            risk = 'High'
                    host_ip      = host_name
                    transport    = ''
                    port         = ''
                    try:
                        plugin_output_url = "https://{0}/scans/{1}/hosts/{2}/plugins/{3}".format(nessus_host,scan_id,host_id,plugin_id)
                        plugin_output_req = requests.get(headers=headers,url=plugin_output_url,verify=False)
                        plugin_content    = plugin_output_req.json()
                        plugin_outputs    = plugin_content['outputs']
                        plugin_outputs    = plugin_outputs[0]
                        plugin_ports      = plugin_outputs['ports'] 
                        port_data         = []
                        for entry in plugin_ports.keys():
                            port_data.append(entry)
                        if(len(port_data) == 1):
                            for entry in port_data:
                                segments  = entry.split(' / ')
                                transport = segments[1]
                                port      = segments[0]
                        else:
                            for entry in port_data:
                                segments  = entry.split(' / ')
                                transport += segments[1]
                                port      += segments[0]
                                transport += ','
                                port      += ','
                            transport = transport.rstrip(',')
                            port = port.rstrip(',')
                    except Exception as e:
                        print("[!] Output plugin query error: {0}".format(e))
                        time.sleep(1)
                        pass
                    synopsis     = ''
                    description  = ''
                    synopsis_url = "https://{0}/plugins/plugin/{1}".format(nessus_host,plugin_id)
                    synopsis_req = requests.get(headers=headers,url=synopsis_url,verify=False)
                    if(synopsis_req.status_code == 200):
                        synopsis_data = synopsis_req.json()
                        for attributes in synopsis_data['attributes']:
                            if(attributes['attribute_name'] == 'synopsis'):
                                synopsis = attributes['attribute_value']
                            if(attributes['attribute_name'] == 'description'):
                                description = attributes['attribute_value']
                                description = description.replace('. ','.\n')
                            if(attributes['attribute_name'] == 'plugin_name'):
                                plugin_name = attributes['attribute_value']
                            if(attributes['attribute_name'] == 'cve'):
                                cve = attributes['attribute_value']
                    if(cvss):
                        status_index  = 'A'+str(row_index)
                        jira_index    = 'B'+str(row_index)
                        name_index    = 'C'+str(row_index)
                        cve_index     = 'D'+str(row_index)
                        cvss_index    = 'E'+str(row_index)
                        risk_index    = 'F'+str(row_index)
                        host_index    = 'G'+str(row_index)
                        proto_index   = 'H'+str(row_index)
                        port_index    = 'I'+str(row_index)
                        synopsis_ind  = 'J'+str(row_index)
                        notes_ind     = 'K'+str(row_index)
                        current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Accepted"'.format(status_index),'format'             : accepted_format})
                        current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Mitigated"'.format(status_index),'format'            : mitigated_format})
                        current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Repair in Progress"'.format(status_index),'format'   : repairing_format})
                        current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Review for Mitigation"'.format(status_index),'format': review_format})
                        current_worksheet.conditional_format(status_index, {'type': 'formula','criteria': '=${0}="Repaired"'.format(status_index),'format': repaired_format})
                        current_worksheet.data_validation(status_index,{'validate':'list','source':['Accepted','Mitigated','Repair in Progress','Review for Mitigation','Repaired']})
                        current_worksheet.write(jira_index,'')
                        current_worksheet.write(name_index,plugin_name)
                        current_worksheet.write(cve_index,cve)
                        current_worksheet.write(cvss_index,cvss)
                        if(risk == 'Low'):
                            current_worksheet.write(risk_index,risk,low_risk_format)
                        if(risk == 'Medium'):
                            current_worksheet.write(risk_index,risk,med_risk_format)
                        if(risk == 'High'):
                            current_worksheet.write(risk_index,risk,high_risk_format)
                        current_worksheet.write(host_index,host_ip)
                        current_worksheet.write(proto_index,transport)
                        current_worksheet.write(port_index,port)
                        current_worksheet.write(synopsis_ind,synopsis)
                        current_worksheet.write(notes_ind,description)
                        row_index += 1
        workbook.close()
        print("[*] Vulnerability record may be located within: %s " % fileName)
    else:
        print("[!] Failed to communicate with the Nessus Server ")
        time.sleep(1)
        sys.exit()

def main():
    print("[*] Nessus Vulnerability Report Tool")
    print("------------------------------------")
    access_key  = input("[+] Enter the Nessus API Access Key -> ")
    secret_key  = input("[+] Enter the Nessus API Secret Key -> ")
    nessus_host = input("[+] Enter the Nessus Server IP or FQDN -> ")
    nessus_port = input("[+] Enter the port for the Nessus Administrative Interface -> ")
    nessus_host = nessus_host + ':' + nessus_port
    print("[~] Attempting communication with: {0}".format(nessus_host))
    CreateVulnRecord(nessus_host,access_key,secret_key)

if(__name__ == '__main__'):
    main()
