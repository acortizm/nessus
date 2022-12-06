#!/usr/bin/env python

import xml.etree.ElementTree as ET
import sys
import os
import argparse

########################
# Defining procedures
########################

def getXMLItem(xmlObject,item):
    retValue = "none"
    try:
        retValue = xmlObject.find(item).text
    except:
        retValue = "none"
    return retValue


def getXMLProperty(xmlObject,property):
    retValue = "none"
    try:
        retValue = xmlObject.get(property)
    except:
        retValue = "none"
    return retValue

def toBoolean(stringValue):
    retValue = 'f'
    stringValue = stringValue.lower()
    if stringValue == 'true' or stringValue == 'exploits are available' or stringValue == 'no exploit is required' :
        retValue = 't'
    return retValue 

def addVulDetail(xmlObject, valueName, stringValue):
    value = ET.SubElement(xmlObject, valueName)
    value.text = stringValue

#################################
# Parsing arguments
#################################

parser = argparse.ArgumentParser(description='Import Nessus Vulnerabilities to Nessus PostgreSQL DB')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--dpwc', action='store_true', help='Import for DPWC Business Unit')
group.add_argument('--npt', action='store_true', help='Import for Neptunia Business Unit')
parser.add_argument('--file', type=argparse.FileType('r'), required=True, help='Nessus XML file')

args = parser.parse_args()

if args.dpwc :
    print('Processing DPWC')
    company = 'ITGOV-54097'
elif args.npt :
    print('Processing Neptunia')
    company = 'ITGOV-54100'

reportFile = args.file.name 

#################################
# Main Code
#################################

print ('Analyzing ' + reportFile)

# Begining of XML parse
print ('Parsing XML...')
tree = ET.parse(reportFile)
root = tree.getroot()
returnCode = 0

# defining XML output file
vuls = ET.Element("Vulnerabilities")

report_key = root.find('Report').get('name').upper()
report_id = os.path.basename(reportFile)
print("Report ID {0}".format(report_id))

print('Processing report ' + report_key)

for reportHost in root.iter('ReportHost') :
    for reportItem in reportHost.findall('ReportItem') :
        sev = getXMLProperty(reportItem, 'severity')
        if sev == '3' or sev == '4' :
            vul = ET.Element("Vulnerability")
            vuls.append(vul)
            addVulDetail(vul, "host_ip", getXMLProperty(reportHost, 'name'))
            addVulDetail(vul, "risk_factor", getXMLItem(reportItem, 'risk_factor').lower())
            addVulDetail(vul, "severity", sev)
            addVulDetail(vul, "solution", getXMLItem(reportItem, 'solution'))
            addVulDetail(vul, "synopsis", getXMLItem(reportItem, 'synopsis'))
            addVulDetail(vul, "description", getXMLItem(reportItem, 'description'))
            addVulDetail(vul, "pugin_name", getXMLItem(reportItem, 'plugin_name'))
            addVulDetail(vul, "plugin_output", getXMLItem(reportItem, 'plugin_output'))
            addVulDetail(vul, "pluginID", getXMLProperty(reportItem, 'pluginID'))
            addVulDetail(vul, "cvss_base_score", getXMLItem(reportItem, 'cvss_base_score'))
            addVulDetail(vul, "exploit_available", getXMLItem(reportItem, 'exploit_available'))
            addVulDetail(vul, "exploitability_ease", getXMLItem(reportItem, 'exploitability_ease'))
            addVulDetail(vul, "exploit_code_maturity", getXMLItem(reportItem, 'exploit_code_maturity'))

document = ET.ElementTree(vuls)

with open ("Vulnerabilities.xml", "wb") as files :
    document.write(files)
            
print ('Done')
