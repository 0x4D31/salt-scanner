#!/usr/bin/env python

from collections import defaultdict
from slackclient import SlackClient

__author__ = 'Adel Ka (0x4d31)'
__version__ = '0.1'

import json
import os
import time
import urllib2
import salt.client
import uuid
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2


#############################[ configuration ]#############################

# OS name in lowercase (e.g. "centos")
# OS version (e.g. "7")
# Set the both values to None for automatic OS and version detection
default_os_name = None
default_os_ver = None

# Bash glob (e.g. "prod-db*") or python list of hosts (e.g. "host1,host2")
hosts_list = "*"

# Set it for sending slack alerts
slack_alert = True
# Use "#something" for public channels or "something" for private channels
slack_channel = "#vulners"

# Leave it empty to write output to the current directory
output_filepath = ""

###########################################################################


VULNERS_LINKS = {'pkgChecker': 'https://vulners.com/api/v3/audit/audit/',
                 'bulletin': 'https://vulners.com/api/v3/search/id/?id=%s'}

ASCII = r"""
 ==========================================================
 _____       _ _     _____                                 
/  ___|     | | |   /  ___|                               
\ `--.  __ _| | |_  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
 `--. \/ _` | | __|  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (_| | | |_  /\__/ / (_| (_| | | | | | | |  __/ |   
\____/ \__,_|_|\__| \____/ \___\__,_|_| |_|_| |_|\___|_|   

 Vulnerability scanner based on Vulners API and Salt Open
===========================================================

"""

hcount = vhcount = id = 0


def get_os(hosts):
    client = salt.client.LocalClient()
    eform = "glob" if '*' in hosts else "list"
    result = client.cmd(hosts, 'cmd.run', ['cat /etc/os-release'], expr_form=eform)
    if result:
        hostsDict = defaultdict(dict)
        osDict = defaultdict(list)
        for key, value in result.iteritems():
            for line in value.split('\n'):
                if "=" in line:
                    k, v = line.rstrip().split("=")
                    if k == "ID":
                        hostsDict[key][k] = v.strip('"')
                    if k == "VERSION_ID":
                        hostsDict[key][k] = v.strip('"')
            if hostsDict[key]["ID"] == "amzn":
                hostsDict[key]["ID"] = "amazon linux"
        for host, info in hostsDict.iteritems():
            keyname = "%s-%s" % (info["ID"], info["VERSION_ID"])
            osDict[keyname].append(host)
        return osDict


def get_packages(osName, hosts):
    client = salt.client.LocalClient()
    eform = "glob" if '*' in hosts else "list"
    if osName in ('debian', 'ubuntu', 'kali'):
        cmd = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'"
    elif osName in ('rhel', 'centos', 'oraclelinux', 'suse', 'fedora', 'amazon linux'):
        cmd = "rpm -qa"
    else:
        cmd = None
    return client.cmd(hosts, 'cmd.run', [cmd], expr_form=eform) if cmd else None


def sendVulnRequest(url, payload):
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'salt-scanner')
    response = urllib2.urlopen(req, json.dumps(payload).encode('utf-8'))
    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)
    return responseData


def audit(packagesDict, osName, osVer):
    global hcount, vhcount
    vhosts = defaultdict(list)
    now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
    starttext = ("{:=^36}\nScan started at {}\n{:=^36}\n:ghost: Scan Results:").format("",now,"")
    if slack_alert:
        slack_alerter(None, starttext)
    filename = ("{}_{}.txt").format(time.strftime("%Y%m%d-%H%M%S", time.localtime()), str(uuid.uuid4()))
    file = ("{}{}").format(output_filepath, filename)
    with open(file, 'w') as f:
        f.write("{}\n".format(starttext))
    for key, value in packagesDict.iteritems():
        hcount += 1
        pkgs = value.splitlines()
        print("+ Started Scanning '{}'...".format(key))
        print("   - Total Packages: {}".format(len(pkgs)))
        payload = {'os': osName,
                   'version': osVer,
                   'package': pkgs}
        url = VULNERS_LINKS.get('pkgChecker')
        response = sendVulnRequest(url, payload)
        resultCode = response.get("result")
        if resultCode == "OK":
            # if response.get('data').get('cvss').get('score') != 0:
            vulnsFound = response.get('data').get('vulnerabilities')
            if not vulnsFound:
                print("   - No vulnerabilities found.")
                with open(file, 'a') as f:
                    f.write("\n\n+ Host: {}\n    No vulnerabilities found.\n".format(key))
                if slack_alert:
                    slack_alerter(key, "ok")
            else:
                vhcount += 1
                if slack_alert:
                    slack_alerter(key, response)
                cvss = response.get('data').get('cvss').get('score')
                if cvss >= 7:
                    severity = "Critical" if cvss >= 9 else "High"
                elif 4 <= cvss < 7:
                    severity = "Medium"
                else:
                    severity = "Low"
                vpcount = 0
                for vp in response.get('data').get('packages'):
                    vpcount += 1
                print("   - {} Vulnerable Packages Found - Severity: {}".format(vpcount, severity))
                vhosts[severity].append(key)
                with open(file, 'a') as f:
                    f.write("\n\n+ Host: {}\n    CVSS Score: {}    Severity: {}\n\n    Vulnerable packages:\n".format(key, cvss, severity))
                payload = {'id': vulnsFound}
                allVulnsInfo = sendVulnRequest(VULNERS_LINKS['bulletin'], payload)
                vulnInfoFound = allVulnsInfo['result'] == 'OK'
                for package in response['data']['packages']:
                    with open(file, 'a') as f:
                        f.write("      {}\n".format(package))
                    packageVulns = []
                    for vulns in response['data']['packages'][package]:
                        if vulnInfoFound:
                            vulnInfo = "{id} - '{title}', cvss.score - {score}".format(id=vulns,
                                                                                       title=allVulnsInfo['data']['documents'][vulns]['title'],
                                                                                       score=allVulnsInfo['data']['documents'][vulns]['cvss']['score'])
                            packageVulns.append((vulnInfo, allVulnsInfo['data']['documents'][vulns]['cvss']['score']))
                        else:
                            packageVulns.append((vulns, 0))
                    packageVulns = [" "*10 + x[0] for x in packageVulns]
                    with open(file, 'a') as f:
                        f.write("\n".join(packageVulns) + "\n")
        else:
            print("Error - %s" % response.get('data').get('error'))

    correct_words = "Hosts are" if vhcount >= 1 else "Host is"
    endtext = "Finished scanning {} host(s). {} {} vulnerable!".format(hcount, vhcount, correct_words)
    print("\n+ {}".format(endtext))
    with open(file, 'a') as f:
        f.write("\n\n{}".format(endtext))
    print("\n+ Writing Output to File: {}".format(file))
    if slack_alert:
        slack_alerter(None, endtext)
        if vhosts:
            slack_alerter(None, vhosts)
        slack_fileUpload(filename, file)


def slack_fileUpload(filename, file):
    slack_token = os.environ["SLACK_API_TOKEN"]
    sc = SlackClient(slack_token)
    sc.api_call('files.upload', channels=slack_channel, filename=filename, file=open(file, 'rb'), title="Full scan results")


def slack_alerter(host, rd):
    global id
    slack_token = os.environ["SLACK_API_TOKEN"]
    sc = SlackClient(slack_token)

    if host is not None:
        if rd == "ok":
            sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=("Host _%s_ is not vulnerable." % host),
                thread_ts=id
            )
        else:
            vpcount = 0
            for vp in rd.get('data').get('packages'):
                vpcount += 1
            vulnpacks = "\n".join(rd.get('data').get('packages'))
            cvss = rd.get('data').get('cvss').get('score')
            if cvss >= 7:
                color = "danger"
                severity = "Critical" if cvss >= 9 else "High"
            elif 4 <= cvss < 7:
                color = "warning"
                severity = "Medium"
            else:
                color = "good"
                severity = "Low"
            att = [{
                "fallback": "scan results",
                "color": color,
                "pretext": ("%d vulnerable packages detected!" % vpcount),
                "title": "Hostname: ",
                "text": host,
                "fields": [
                    {
                        "title": "CVSS Score",
                        "value": cvss,
                        "short": "true"
                    },
                    {
                        "title": "Severity",
                        "value": severity,
                        "short": "true"
                    },
                    {
                        "title": "Vulnerable Packages",
                        "value": vulnpacks
                    }
                ],
                "footer": "Vulners",
                "footer_icon": "https://pbs.twimg.com/profile_images/711948370332545025/0A-995CX.jpg",
                "ts": id
            }]
            sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=("Host _%s_ is vulnerable :scream:" % host),
                attachments=json.dumps(att),
                thread_ts=id
            )
    else:
        if type(rd) is str:
            response = sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=(rd)
            )
            id = response['ts']
        else:
            for sev, hosts in rd.iteritems():
                vulnhosts = "\n".join(hosts)
                if sev == ("Critical" or "High"):
                    color = "danger"
                elif sev == "Medium":
                    color = "warning"
                else:
                    color = "good"
                att = [{
                    "fallback": "scan results - summary",
                    "color": color,
                    "title": "Severity",
                    "text": sev,
                    "fields": [
                        {
                            "title": "Hosts",
                            "value": vulnhosts
                        }
                    ],
                    "footer": "Vulners",
                    "footer_icon": "https://pbs.twimg.com/profile_images/711948370332545025/0A-995CX.jpg",
                    "ts": id
                }]
                sc.api_call(
                    "chat.postMessage",
                    channel=slack_channel,
                    text=("Summary Report:"),
                    attachments=json.dumps(att),
                    thread_ts=id
                )


def main():
    os_name = os_ver = ""
    if all([default_os_name, default_os_ver]):
        print("+ Default OS: {}, Version: {}".format(default_os_name, default_os_ver))
        os_name, os_ver = default_os_name, default_os_ver
        print("+ Getting the Installed Packages...")
        pdict = get_packages(os_name, hosts_list)
        audit(pdict, os_name, os_ver)
    else:
        print("+ No default OS is configured. Detecting OS...")
        os_dict = get_os(hosts_list)
        if os_dict:
            print("+ Detected Operating Systems:")
            for os_nameVer, hlist in os_dict.iteritems():
                os_info = os_nameVer.split('-')
                print("   - OS Name: {}, OS Version: {}".format(os_info[0], os_info[1]))
                print("+ Getting the Installed Packages...")
                hosts = ','.join(hlist)
                pdict = get_packages(os_info[0], hosts)
                audit(pdict, os_info[0], os_info[1])


if __name__ == '__main__':
    print('\n'.join(ASCII.splitlines()))
    main()
