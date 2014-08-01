PyAuditingTool
==============
PyAuditingTool: A tool to test GNU/Linux security and its misconfiguration

For now, it checks: 

- Global system info
- Enumerating users with login access & group id 0
- Enumerating system users and password policy 
- Stat on binary files defined via config.cfg (uid,gid,owner,groupowner checks)
- Check users in /etc/sudoers
- Check SSH configuration 
- Check OpenSSL version for heartbleed vulnerability
- Check Apache2 configuration (several config parameters)
- Check Integrity on binary files defined via config.cfg (two modes: 'since run' or md5sum on packages)


** I have start to develop this tool on July 29, 2014
Not finished yet ! Not fully completed.
Come back later ... ;)



Wiki
==============

https://github.com/tunelko/PyAuditingTool/wiki
