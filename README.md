# salt-scanner
A linux vulnerability scanner based on Vulners Audit API and Salt Open, with Slack notifications and JIRA integration.

## Features
* Slack notification and report upload
* JIRA integration
* OpsGenie integration

## Requirements
* [Salt Open](https://saltstack.com/salt-open-source/) (salt-master, salt-minion)¹
* Python 2.7
* salt _(you may need to install gcc, gcc-c++, python dev)_
* slackclient
* jira
* opsgenie-sdk

## Usage
```
[root@localhost ~]# sudo SLACK_API_TOKEN="EXAMPLETOKEN" python salt-scanner.py

 ==========================================================
 _____       _ _     _____                                 
/  ___|     | | |   /  ___|                               
\ `--.  __ _| | |_  \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
 `--. \/ _` | | __|  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (_| | | |_  /\__/ / (_| (_| | | | | | | |  __/ |   
\____/ \__,_|_|\__| \____/ \___\__,_|_| |_|_| |_|\___|_|   

 Vulnerability scanner based on Vulners API and Salt Open
===========================================================

+ No default OS is configured. Detecting OS...
+ Detected Operating Systems:
   - OS Name: centos, OS Version: 7
+ Getting the Installed Packages...
+ Started Scanning '10.10.10.55'...
   - Total Packages: 357
   - 6 Vulnerable Packages Found - Severity: Low
+ Started Scanning '10.10.10.56'...
   - Total Packages: 392
   - 6 Vulnerable Packages Found - Severity: Critical

+ Finished scanning 2 host(s). 2 Hosts are vulnerable!

+ Output file created: 20170622-093138_232826a7-983f-499b-ad96-7b8f1a75c1d7.txt
+ Full report uploaded to Slack
+ JIRA Issue created: VM-16
+ OpsGenie alert created
```
## Slack Alert
![Salt-Scanner](https://github.com/0x4D31/salt-scanner/blob/master/docs/slack-alert_full.jpg)

## TODO
+ Clean up the code and add some error handling
+ Use Salt Grains for getting the OS info and installed packages

---

[1] Salt in 10 Minutes: https://docs.saltstack.com/en/latest/topics/tutorials/walkthrough.html
