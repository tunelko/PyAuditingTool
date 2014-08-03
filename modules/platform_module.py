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


class platform_module(object):
		''' Class that handles any service checks'''

		def __init__(self, cfg_filepath='config.cfg'):
				self.current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]
				self.atdatetime = str(datetime.date(datetime.now())) + '_at_' + str(self.current_time())
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
				self.report_name = 'tmp_report_' + self.atdatetime + '.txt'
				

		# Dummy separator 
		def separator(self,attrs=''): 
				print colored('='*99, self.cinfo,attrs='') 
				return ''

		
	# get uname() 
		def get_platform(self):
			return colored('[INFO] Platform: ' + platform.platform(), self.cinfo, attrs=['bold'])

	# get distribution 
		def get_dist(self):
			return colored('[INFO] Distribution: ' + ' '.join((platform.linux_distribution())), self.cinfo, attrs=['bold']) 

	# get arquitecture
		def get_arquitecture(self):
			return colored('[INFO] Machine: ' + ''.join((platform.machine())), self.cinfo, attrs=['bold']) 
			
