PyAuditingTool
==============
PyAuditingTool: A tool to test GNU/Linux security and its misconfiguration

For now, it checks: 

- Global system info (platform, arquitecture, alias, ...)
- Check users with login access & group id 0
- Check password policy age 
- Check last 20 commands of each user 
- Check uid,gid,owner,groupowner on binary files defined via config.cfg
- Check users in /etc/sudoers
- Check SSH configuration 
- Check OpenSSL version for heartbleed vulnerability
- Check Apache2 configuration (several config parameters)
- Check sysctl.conf 
- Check Integrity (md5sums) on binary files defined via config.cfg with two modes: 'since run' or md5sum on packages


** I have start to develop this tool on July 29, 2014
Not finished yet ! Not fully completed.
Come back later ... ;)


Usage
==============

    $ ./PyAuditingTool.py -h 
    usage: PyAuditingTool.py [-h] [-v] [-c] [-f SET_FORMAT [SET_FORMAT ...]]
                           [-ro RUN_ONLY [RUN_ONLY ...]] [-ca] [-ff] [-u]
    
    PyAuditingTool: A tool to test GNU/Linux security and configuration !
    
    optional arguments:
    -h, --help            show this help message and exit
    -v, --version         show version
    -c, --create-report   create report (default HTML format)
    -f SET_FORMAT [SET_FORMAT ...], --format SET_FORMAT [SET_FORMAT ...]
                          Available report formats: HTML(default), CSV, XML, TXT
    -ro RUN_ONLY [RUN_ONLY ...], --run-only RUN_ONLY [RUN_ONLY ...]
                          Run only a check: global_info, users, services,
                          integrity
    -ca, --cache          Do not start over again, get cached data
    -ff, --flush          Delete any previous data
    -u, --update          Update to the lastest version of PyAuditingTool

Mini howto
==============

1. First, run [install.sh](https://github.com/tunelko/PyAuditingTool/blob/master/install.sh) to meet dependencies. 
2. In the first run, the tool collects some information for integrity checks, asking you to re-run it (it's normal)

Reports
==============
You can create reports in several common formats: HTML, XML, CSV, TXT with --format [FORMAT] option. Reports will be stored on reports folder. HTML is the default one. 


Wiki
==============

Please visit wiki section form more detailed information: 
https://github.com/tunelko/PyAuditingTool/wiki

