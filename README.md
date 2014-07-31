PyAuditingTool
==============
PyAuditingTool: A tool to test GNU/Linux security and configuration

For now, it checks: 

- Global system info
- Enumerating users with login access & group id 0
- Enumerating system users and password policy 
- Stat on binary files defined via config.cfg (uid,gid,owner,groupowner checks)
- Check users in /etc/sudoers
- Check SSH configuration 
- Check Apache2 configuration
- Check Integrity on binary files defined via config.cfg (two modes: 'since run' or md5sum on packages)


Not finished yet ! Not fully completed.
Come back later ... ;)



Wiki
==============

https://github.com/tunelko/PyAuditingTool/wiki
