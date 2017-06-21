# salt-scanner
A linux vulnerability scanner based on Vulners Audit API and Salt Open, with Slack notifications and JIRA integration.

## Requirements
* [Salt Open](https://saltstack.com/salt-open-source/) (salt-master, salt-minion)¹
* Python 2.7
* Salt _(you may need to install gcc, gcc-c++, python dev)_
* Slackclient
* Jira

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
   - Total Packages: 391
   - 6 Vulnerable Packages Found - Severity: Critical

+ JIRA Issue: VM-16

+ Finished scanning 2 host(s). 2 Hosts are vulnerable!

+ Writing Output to File: 20170621-155936_fd56e3e0-16bb-41b0-8e96-90b6fe542aa9.txt
```
## Slack Alert
![Salt-Scanner](https://github.com/0x4D31/salt-scanner/blob/master/docs/slack-alert_full.jpg)

## TODO
+ Documentation
+ More alerting modules
   - JIRA ✓
   - OpsGenie / PagerDuty
+ Clean up the code and add some error handling
+ Use Salt Grains for getting the OS info and installed packages

---

[1] Salt in 10 Minutes: https://docs.saltstack.com/en/latest/topics/tutorials/walkthrough.html
