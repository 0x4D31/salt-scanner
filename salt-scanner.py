#!/usr/bin/env python

from collections import defaultdict
from slackclient import SlackClient
from opsgenie.swagger_client import AlertApi
from opsgenie.swagger_client import configuration
from opsgenie.swagger_client.rest import ApiException
from opsgenie.swagger_client.models import *
from jira import JIRA
import json
import os
import time
import salt.client
import uuid
import sys
import re
import argparse
import tempfile
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

__author__ = 'Adel "0x4d31" Ka'
__version__ = '0.1'

#############################[ configuration ]#############################

# OS name in lowercase (e.g. "centos")
# OS version (e.g. "7")
# Set the both values to None for automatic OS and version detection
default_os_name = None
default_os_ver = None

# Bash glob (e.g. "prod-db*") or python list of hosts (e.g. "host1,host2")
target_hosts = "*"

# Slack Alert
slack_alert = False
# Set your Slack API Token here.
# Alternatively, you can use the environment variable SLACK_API_TOKEN
slack_api_token = "SLAKCAPITOKENEXAMPLE"
# Use "#something" for public channels or "something" for private channels
slack_channel = "#vulners"

# Minimum CVSS score for creating a JIRA issue or OpsGenie alert
alert_score = 7

# JIRA Alert
#  creates an issue per scan (not per vulnerable host)
jira_alert = False
jira_server = "https://yourcompany.atlassian.net"
jira_user = "user"
jira_pass = "pass"
issue_type = "Task"
issue_projectKey = "VM"
issue_summary = "New issue from Salt-Scanner"
issue_priority = "Critical"

# OpsGenie Alert
#  creates an alert per scan (not per vulnerable host)
opsgenie_alert = False
opsgenie_api_key = "d94de12d-4ds1-4d40-b211-EXAMPLE"
opsgenie_taglist = ['security', 'devops', 'vuln']
opsgenie_entity = "Prod-servers"
opsgenie_message = "New alert from Salt-Scanner"
# Priority of the alert. Should be one of P1, P2, P3 (default), P4, or P5:
#   P1-Critical, P2-High, P3-Moderate, P4-Low, P5-Informational
opsgenie_priority = "P1"

###########################################################################


VULNERS_LINKS = {'pkgChecker': 'https://vulners.com/api/v3/audit/audit/',
                 'bulletin': 'https://vulners.com/api/v3/search/id/?id=%s'}

ASCII = r"""
 ==========================================================
  Vulnerability scanner based on Vulners API and Salt Open
 _____       _ _     _____                                 
/  ___|     | | |   /  ___|                               
\ `--.  __ _| | |_  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
 `--. \/ _` | | __|  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (_| | | |_  /\__/ / (_| (_| | | | | | | |  __/ |   
\____/ \__,_|_|\__| \____/ \___\__,_|_| |_|_| |_|\___|_|   

               Salt-Scanner 0.1 / by 0x4D31               
 ==========================================================

"""

hcount = vhcount = id = 0


def get_os(hosts, form):
    client = salt.client.LocalClient()
    result = client.cmd(
        hosts, 'cmd.run',
        ['cat /etc/os-release'],
        expr_form=form
    )
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


def get_packages(osName, hosts, form):
    client = salt.client.LocalClient()
    if osName in ('debian', 'ubuntu', 'kali'):
        cmd = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'"
    elif osName in ('rhel', 'centos', 'oraclelinux', 'suse',
                    'fedora', 'amazon linux', 'amazon'):
        cmd = "rpm -qa"
    else:
        cmd = None
    return client.cmd(
        hosts,
        'cmd.run',
        [cmd],
        expr_form=form
    ) if cmd else None


def get_kernel(host, osName):
    client = salt.client.LocalClient()
    res = client.cmd(
        host,
        'cmd.run',
        ["uname -r"]
    )
    if osName in ('rhel', 'centos', 'oraclelinux', 'suse',
                  'fedora', 'amazon linux', 'amazon'):
        return "kernel-{}".format(res[host])
    elif osName in ('debian', 'ubuntu', 'kali'):
        return "linux-image-{}".format(res[host])


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


def audit(packagesDict, osName, osVer, tgt_hosts):
    global hcount, vhcount
    # vhosts contains the list of vulnerable hosts by severity
    # {'SEVERITY': [list of hosts]}
    vhosts = defaultdict(list)
    # vdict contains the list of vulnerable hosts, overall CVSS score & vector,
    # and vulnerable packages. Will use this for creating JIRA issues and etc.
    # {'HOST': {'cvss_score':'SCORE', 'cvss_vector':'VECTOR',
    #  'vuln_pkgs': 'list of vulnerable packages'}}
    vdict = defaultdict(dict)
    now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
    starttext = ("{:=^36}\nScan started at {}\n{:=^36}\n:ghost: Scan Results:"
                 ).format("", now, "")
    if slack_alert:
        slack_alerter(None, starttext)
    filename = ("{}_{}.txt").format(
        time.strftime("%Y%m%d-%H%M%S", time.localtime()), str(uuid.uuid4())
    )
    file = os.path.join(tempfile.gettempdir(), filename)
    with open(file, 'w') as f:
        f.write("{}\n".format(starttext))
    for key, value in packagesDict.iteritems():
        hcount += 1
        init_pkgs = value.splitlines()
        # remove kernel packages from the list
        r = re.compile('kernel-[0-9]')
        r2 = re.compile('linux-image-[0-9]')
        pkgs = filter(lambda i: not (r.match(i) or r2.match(i)), init_pkgs)
        # OR pkgs = [i for i in init_pkgs if not r.match(i)]
        # add kernel package to the list, based on uname:
        kernelpkg = get_kernel(key, osName)
        if kernelpkg:
            pkgs.append(kernelpkg)
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
                    f.write("\n\n+ Host: {}\n    No vulnerabilities found.\n"
                            .format(key))
                if slack_alert:
                    slack_alerter(key, "ok")
            else:
                vhcount += 1
                if slack_alert:
                    slack_alerter(key, response)
                cvss_vector = response.get('data').get('cvss').get('vector')
                cvss_score = response.get('data').get('cvss').get('score')
                vuln_pkgs = ",".join(response.get('data').get('packages'))
                if ((jira_alert or opsgenie_alert) and
                        cvss_score >= alert_score):
                    vdict[key]['cvss_score'] = cvss_score
                    vdict[key]['cvss_vector'] = cvss_vector
                    vdict[key]['vuln_pkgs'] = vuln_pkgs
                if cvss_score >= 7:
                    severity = "Critical" if cvss_score >= 9 else "High"
                elif 4 <= cvss_score < 7:
                    severity = "Medium"
                else:
                    severity = "Low"
                vpcount = 0
                for vp in response.get('data').get('packages'):
                    vpcount += 1
                print("   - {} Vulnerable Packages Found - Severity: {}"
                      .format(vpcount, severity))
                vhosts[severity].append(key)
                with open(file, 'a') as f:
                    f.write("\n\n+ Host: {}\n    CVSS Score: {}    Severity: {}\n\n    Vulnerable packages:\n"
                            .format(key, cvss_score, severity))
                payload = {'id': vulnsFound}
                allVulnsInfo = sendVulnRequest(
                    VULNERS_LINKS['bulletin'], payload)
                vulnInfoFound = allVulnsInfo['result'] == 'OK'
                for package in response['data']['packages']:
                    with open(file, 'a') as f:
                        f.write("      {}\n".format(package))
                    packageVulns = []
                    for vulns in response['data']['packages'][package]:
                        if vulnInfoFound:
                            vulnInfo = ("{id} - '{title}', CVSS Score: {score}"
                                        .format(id=vulns,
                                                title=allVulnsInfo['data']['documents'][vulns]['title'],
                                                score=allVulnsInfo['data']['documents'][vulns]['cvss']['score']))
                            packageVulns.append(
                                vulnInfo,
                                allVulnsInfo['data']['documents'][vulns]['cvss']['score'])
                        else:
                            packageVulns.append((vulns, 0))
                    packageVulns = [" "*10 + x[0] for x in packageVulns]
                    with open(file, 'a') as f:
                        f.write("\n".join(packageVulns) + "\n")
        else:
            print("Error - %s" % response.get('data').get('error'))
    correct_words = "Hosts are" if vhcount >= 1 else "Host is"
    endtext = ("Finished scanning {} hosts (target hosts: '{}').\n{} {} vulnerable!"
               .format(hcount, tgt_hosts, vhcount, correct_words))
    print("\n+ {}\n".format(endtext))
    with open(file, 'a') as f:
        f.write("\n\n{}".format(endtext))
    print("+ Output file created: {}".format(file))
    if slack_alert:
        slack_alerter(None, endtext)
        if vhosts:
            slack_alerter(None, vhosts)
        slack_fileUpload(filename, file)
    if jira_alert and vdict:
        jira_alerter(vdict)
    if opsgenie_alert and vdict:
        opsgenie_alerter(vdict)


def slack_tokenCheck():
        try:
            slack_api_token
        except NameError:
            if "SLACK_API_TOKEN" in os.environ:
                return
            else:
                print("Error: Missing Slack API Token")
                sys.exit(1)


def slack_fileUpload(filename, file):
    global slack_api_token
    try:
        slack_api_token
    except NameError:
        slack_api_token = os.environ["SLACK_API_TOKEN"]
    sc = SlackClient(slack_api_token)
    response = sc.api_call(
        'files.upload',
        channels=slack_channel,
        filename=filename,
        file=open(file, 'rb'),
        title="Full scan results")
    if not response['ok']:
        print("Slack Error: {}".format(response['error']))
    else:
        print("+ Full report uploaded to Slack")


def slack_alerter(host, rd):
    global id, slack_api_token
    try:
        slack_api_token
    except NameError:
        slack_api_token = os.environ["SLACK_API_TOKEN"]
    sc = SlackClient(slack_api_token)

    if host is not None:
        if rd == "ok":
            response = sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=("Host _%s_ is not vulnerable." % host),
                thread_ts=id
            )
            if not response['ok']:
                print("Slack Error: {}".format(response['error']))
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
            response = sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=("Host _%s_ is vulnerable :scream:" % host),
                attachments=json.dumps(att),
                thread_ts=id
            )
            if not response['ok']:
                print("Slack Error: {}".format(response['error']))
    else:
        if type(rd) is str:
            response = sc.api_call(
                "chat.postMessage",
                channel=slack_channel,
                text=(rd)
            )
            if not response['ok']:
                print("Slack Error: {}".format(response['error']))
                sys.exit(1)
            else:
                id = response['ts']
        else:
            for sev, hosts in rd.iteritems():
                vulnhosts = "\n".join(hosts)
                if sev in ("Critical", "High"):
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
                response = sc.api_call(
                    "chat.postMessage",
                    channel=slack_channel,
                    text=("Summary Report:"),
                    attachments=json.dumps(att),
                    thread_ts=id
                )
                if not response['ok']:
                    print("Slack Error: {}".format(response['error']))


def jira_alerter(result):
    jira_options = {'server': jira_server}
    jira = JIRA(options=jira_options, basic_auth=(jira_user, jira_pass))
    issue_description = "List of the vulnerable hosts: \n"
    for host, value in result.iteritems():
        issue_description += ("[+] {}\n   CVSS Score: {}\n   CVSS Vector: {}\n   Packages: {}\n"
                              .format(host,
                                      value['cvss_score'],
                                      value['cvss_vector'],
                                      value['vuln_pkgs']))
    issue_dict = {
        'project': {'key': issue_projectKey},
        'summary': issue_summary,
        'description': issue_description,
        'issuetype': {'name': issue_type},
        'priority': {'name': issue_priority}
    }
    new_issue = jira.create_issue(fields=issue_dict)
    print("+ JIRA issue created: {}".format(new_issue))


def opsgenie_alerter(result):
    configuration.api_key['Authorization'] = opsgenie_api_key
    configuration.api_key_prefix['Authorization'] = 'GenieKey'
    issue_description = "List of the vulnerable hosts: \n"
    for host, value in result.iteritems():
        issue_description += ("[+] {}\n   CVSS Score: {}\n   CVSS Vector: {}\n   Packages: {}\n"
                              .format(host,
                                      value['cvss_score'],
                                      value['cvss_vector'],
                                      value['vuln_pkgs']))
    body = CreateAlertRequest(
        message=opsgenie_message,
        description=issue_description,
        tags=opsgenie_taglist,
        entity=opsgenie_entity,
        priority=opsgenie_priority,
        source='Salt-Scanner',
        # teams=[TeamRecipient(name='ops_team')],
        # visible_to=[TeamRecipient(name='ops_team', type='team')],
        note='Alert created')
    try:
        AlertApi().create_alert(body=body)
        print("+ OpsGenie alert created")
    except ApiException as err:
        print("OpsGenie - Exception when calling AlertApi->create_alert: %s"
              % err)


def parse_cmd_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--target-hosts',
        type=str,
        default=target_hosts
        # help='Bash glob (e.g."prod-db*") or \
        # python list of hosts (e.g."host1,host2")'
    )
    parser.add_argument(
        '-tF', '--target-form',
        type=str,
        default='glob',
        choices=["glob", "list", "grain"]
        # help='Bash glob (e.g."prod-db*") or \
        # python list of hosts (e.g."host1,host2"), or \
        # Salt grains (e.g. "os:amazon" or "ec2_tags:role:webapp")'
    )
    parser.add_argument(
        '-oN', '--os-name',
        type=str,
        default=default_os_name
        # help='Default OS name'
    )
    parser.add_argument(
        '-oV', '--os-version',
        type=str,
        default=default_os_ver
        # help='Default OS version'
    )
    return parser.parse_args()


def main():
    args = parse_cmd_line_args()
    if slack_alert:
        slack_tokenCheck()

    # If default OS and Version is set
    if all([args.os_name, args.os_version]):
        print("+ Default OS: {}, Version: {}".format(
            args.os_name, args.os_version
        ))
        print("+ Getting the Installed Packages...")
        pdict = get_packages(
            args.os_name,
            args.target_hosts,
            args.target_form
        )
        if pdict:
            audit(
                pdict,
                args.os_name,
                args.os_version,
                args.target_hosts
            )
        else:
            print("Error: package list is empty")
    # No default OS and Verison is set; Detecting the OS automatically
    else:
        print("+ No default OS is configured. Detecting OS...")
        os_dict = get_os(
            args.target_hosts,
            args.target_form
        )
        if os_dict:
            print("+ Detected Operating Systems:")
            for os_nameVer, hlist in os_dict.iteritems():
                os_info = os_nameVer.split('-')
                print("   - OS Name: {}, OS Version: {}".format(
                    os_info[0],
                    os_info[1]))
                print("+ Getting the Installed Packages...")
                hosts = ','.join(hlist)
                pdict = get_packages(
                    os_info[0],
                    hosts,
                    "list"
                )
                if pdict:
                    audit(
                        pdict,
                        os_info[0],
                        os_info[1],
                        args.target_hosts
                    )
                else:
                    print("Error: package list is empty")


if __name__ == '__main__':
    print(ASCII)
    main()
