#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on June 30, 2014
@author: @tunelko
'''

import os, re 
from datetime import datetime
from termcolor import colored, cprint 
import platform
try:
    import git
except ImportError:
    print colored('[ERROR] You need to install python-git, run install.sh', 'red', attrs=['bold'])
    exit(0)



class update_module(object):
		''' Class that handles update from github '''

		def __init__(self, update_path='.'):
				self.current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]
				self.min_days = 60  # 2 months password changes
				self.last_days = 60  
				self.max_days = 60

				self.cwarning = 'red'
				self.cinfo = 'blue' 
				self.calert = 'yellow'
				self.cok = 'green'
				self.cdefault = 'green' 
				self.symalert = '**' 
				#paths 
				self.data_path = 'data/'
				self.reports_path = 'reports/'
				# report name  
				self.report_name = 'tmp_report_' + str(datetime.date(datetime.now())) + '__' + str(self.current_time()) + '.txt'                
				self.update_path = update_path

		# Dummy separator 
		def separator(self,attrs=''): 
				print colored('='*99, self.cinfo,attrs='') 
				return ''

		def update(self):
			try:
				git.cmd.Git(self.work_directory).pull()
			except git.GitCommandError, e:
				print e