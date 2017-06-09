# salt-scanner
Vulnerability scanner based on Salt Open and Vulners audit API

### Test:
```
root@localhost ~]# sudo SLACK_API_TOKEN="EXAMPLETOKEN" python salt-scanner.py

===========================================================
 _____       _ _     _____
/  ___|     | | |   /  ___|
\ `--.  __ _| | |_  \ `--.  ___ __ _ _ __  _ __   ___ _ __
 `--. \/ _` | | __|  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (_| | | |_  /\__/ / (_| (_| | | | | | | |  __/ |
\____/ \__,_|_|\__| \____/ \___\__,_|_| |_|_| |_|\___|_|

                                          Using Vulners API
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

### TODO:
+ Documentation
+ ...
