# salt-scanner
Vulnerability Scanner based on Vulners Audit API and Salt Open

### Test:
```
[root@localhost ~]# sudo SLACK_API_TOKEN="EXAMPLETOKEN" python salt-scanner.py

===========================================================
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
   - Total Packages: 354
   - 7 Vulnerable Packages Found - Severity: Critical
+ Started Scanning '10.10.10.56'...
   - Total Packages: 332
   - 66 Vulnerable Packages Found - Severity: Critical

+ Finished scanning 2 host(s). 2 Hosts are vulnerable!

+ Writing Output to File: 20170609-115923_b0575ead-c5f1-4ef1-9439-7249afa9d9e6.txt
```
### Slack Alert:
![Salt-Scanner](https://github.com/0x4D31/salt-scanner/blob/master/docs/slack-alert_full.jpg)

### TODO:
+ Documentation
+ Clean up the code and add some error handling
+ Use Salt Grains for getting the OS info and installed packages
