#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on June 30, 2014
@author: @tunelko
'''

import os
import sys
import ConfigParser


class config_manager(object):
    ''' Class that handles any user-controlled settings '''

    # Feature enable/disable
    _integrity_check_dirs = None

    def __init__(self, cfg_file='config.cfg'):
        self.filename = cfg_file
        if os.path.exists(cfg_file) and os.path.isfile(cfg_file):
            self.conf_path = os.path.abspath(cfg_file)
        else:
            sys.stderr.write(WARN + "No configuration file found at: %s." % self.conf_path)
            os._exit(1)
        self.refresh()
        

    def refresh(self):
        ''' Refresh config file settings '''
        self.config = ConfigParser.SafeConfigParser()
        with open(self.conf_path, 'r') as fp:
            self.config.readfp(fp)

    def save(self):
        ''' Write current config to file '''
        # Set game config
        self.config.set("Integrity", "integrity_check_dirs", self._integrity_paths)
        with open(self.conf_path, 'w') as fp:
            self.config.write(fp)

    def get_integrity_paths(self):
        return self.config.get("Integrity", 'integrity_check_dirs')

    def get_md5packages_paths(self):
        return self.config.get("Integrity", 'md5packages_paths')

    def get_stat_paths(self):
        return self.config.get("System", 'stat_check_dirs')
    
    def get_sshd_path(self):
            return self.config.get("Services", 'sshd_path')
    
    def get_sshd_variables2check(self):
            return self.config.get("Services", 'sshd_variables2check')

    def get_apache2_path(self):
            return self.config.get("Services", 'apache2_path')

    def get_apache2_variables2check(self):
            return self.config.get("Services", 'apache2_variables2check')

    def get_sudoers_path(self):
            return self.config.get("System", 'sudoers_path')

    def get_sysctl_path(self):
            return self.config.get("Services", 'sysctl_path')

    def get_sysctl_variables2check(self):
            return self.config.get("Services", 'sysctl_variables2check')
    

            


