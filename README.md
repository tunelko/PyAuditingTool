PyAuditingTool
==============
PyAuditingTool: A opensource tool to test GNU/Linux security and misconfiguration. The main goal is scan, review and audit to make recommendations and fix the problems hardening the system. The tests are part of common security guidelines and standards. All is include in common format's reports. 

For now, it checks: 

- Global system info (platform, arquitecture, alias, ...)
- Check users with login access & group id 0
- Check password policy age 
- Show last 'number' of commands of each user (number defined via config.cfg) 
- Check uid,gid,owner,groupowner on binary files defined via config.cfg
- Check users in /etc/sudoers 
- Check SSH configuration (several config parameters)
- Check OpenSSL version for heartbleed vulnerability
- Check Apache2 configuration (minimal config parameters)
- Check PHP5 configuration (minimal config parameters)
- Check sysctl.conf (several config parameters)
- Check Integrity (md5sums) on binary files defined via config.cfg with two modes:
    - Via local compare
    - MD5sums on packages

** I have start to develop this tool on July 29, 2014
Not finished yet ! Not fully completed.
Come back later ... ;)


Usage
==============

    usage: PyAuditingTool.py [-h] [-v] [-c] [-f SET_FORMAT [SET_FORMAT ...]]
                             [-ro RUN_ONLY [RUN_ONLY ...]] [-ca] [-ff] [-u]
    
    PyAuditingTool: A tool to test GNU/Linux security and configuration !
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         show version
      -f SET_FORMAT [SET_FORMAT ...], --format SET_FORMAT [SET_FORMAT ...]
                            Available report formats: HTML(default), CSV, XML, TXT
      -ro RUN_ONLY [RUN_ONLY ...], --run-only RUN_ONLY [RUN_ONLY ...]
                            Run only a check: 'global_info', 'users', 'services',
                            'integrity [local_compare]'
      -ca, --cache          Do not start over again, get cached data
      -ff, --flush          Delete any previous data
      -u, --update          Update to the last version of PyAuditingTool


How to start?
==============

First, run [install.sh](https://github.com/tunelko/PyAuditingTool/blob/master/install.sh) to meet dependencies. 
Then, give a try with: 

    $ ./PyAuditingTool.py -h

Reports
==============
You can access to a complete report once tasks are finished. It uses tornado webserver and its templating ui to render all the data. If you want to export data, there are several formats availables. All in a fancy way with bootstrap css elements. 

Wiki
==============

Please visit wiki section form more detailed information: 
https://github.com/tunelko/PyAuditingTool/wiki


