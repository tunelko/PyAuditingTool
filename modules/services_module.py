#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Created on June 30, 2014
@author: @tunelko
'''

import os, re 
import spwd, pwd, grp 
from datetime import datetime
from termcolor import colored, cprint 
import commands


class services_module(object):
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

	# Check heartbleed vulnerability. version checking only. 
	def check_heartbleed(self):
			status, sshv =  commands.getstatusoutput("dpkg -s openssl | grep Version:.*$")
			status, heartbleed_vuln =  commands.getstatusoutput("dpkg -s openssl | grep -Ei '\b(Version: (1)\W+)\b'")

			if heartbleed_vuln != '':           
				print colored('[INFO] OpenSSL version (vulnerable):' + sshv, self.cwarning, attrs=['bold'])
				self.separator()
			else:
				print colored('[INFO] OpenSSL version (not vulnerable):' + sshv, self.cok,attrs=['bold'])
				self.separator()


	# Check any service with delimiter (via config values)
	def check_services(self, filepath, params = [], delimiter=' '):
		try:
			variables=[]       
			variables_ok=[]
			variables_nok=[]

			with open(filepath, 'r') as f:
				for line in f:					
					pairs = filter(lambda x:x != '', line.split(delimiter))					
					if len(pairs)==2:
						key = re.sub('\n','',pairs[0])
						value = re.sub('\n','',pairs[1])
						variables.append(key + ' ' + value)


			for valc in params:       
				for val in variables:
					if val in valc:
						print colored('[INFO] Value OK: ' + val,self.cok,attrs=['bold'])
						variables_ok.append(val)
					else:						
						variables_nok.append(val)

			resulting_list = list(set(variables_nok) - set(variables_ok))			
			#print resulting_list

			for val in resulting_list:				
				if val.startswith("#"):					
					print colored('[WARN] Value is commented and not processed by the filters: ' + val,self.cwarning,attrs=['bold'])
				if delimiter ==' = ':
					if val.startswith(";"):
						print colored('[WARN] Value is commented and not processed by the filters: ' + val,self.cwarning,attrs=['bold'])
						continue
					else:
						#print colored('[WARN] Please, Check this value NOT in the filters: ' + val,self.cinfo,attrs=['bold'])
						continue

		except IOError, e:
				print colored('[ERROR] filepath not found, check config value [service_path] = ' + filepath, self.cwarning,attrs=['bold'] )
				return ''
		