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
		

	# Dummy separator 
	def separator(self,attrs=''): 
		print colored('='*99, self.cinfo,attrs='') 
		return ''


	# Check SSH config (via config values)
	def check_sshd(self, filepath, params=[] ):

		try:
			sshd_variables=[]       
			sshd_variables_ok=[]
			sshd_variables_nok=[]

			status, sshv =  commands.getstatusoutput("dpkg -s openssl | grep Version:.*$")
			status, heartbleed_vuln =  commands.getstatusoutput("dpkg -s openssl | grep -Ei '\b(Version: (1)\W+)\b'")

			if heartbleed_vuln != '':           
				print colored('[INFO] OpenSSL version (vulnerable):' + sshv, self.cwarning, attrs=['bold'])
				self.separator()
			else:
				print colored('[INFO] OpenSSL version (not vulnerable):' + sshv, self.cok,attrs=['bold'])
				self.separator()

			with open(filepath, 'r') as f:
				for line in f:
					pairs =  line.split(' ')
					if len(pairs)==2:
						key = pairs[0]
						value = re.sub('\n','',pairs[1])
						sshd_variables.append(key+' ' +value)

			for valc in params:       
				for val in sshd_variables:
					if val in valc:
						print colored('[INFO] Value OK: ' + val,self.cok,attrs=['bold'])
						sshd_variables_ok.append(val)
					else:               
						sshd_variables_nok.append(val)

			resulting_list = list(set(sshd_variables_nok) - set(sshd_variables_ok))
			for val in resulting_list:      
				if re.sub(r'#.*$','',val):
					print colored('[WARN] Value not match, commented or not include in filters: ' + val,self.cwarning,attrs=['bold'])

		except IOError, e:
				print colored('[ERROR] filepath not found, check config value: ssh2_path = ' + filepath, self.cwarning,attrs=['bold'] )
				return ''
		
	# Check Apache2 config (via config values)
	def check_apache2(self, filepath, params ):
		try:
			apache2_variables=[]
			apache2_variables_ok=[]
			apache2_variables_nok=[]

			with open(filepath, 'r') as f:
					for line in f:
						pairs =  line.split(' ')
						if len(pairs)==2:
							key = pairs[0]
							value = re.sub('\n','',pairs[1])
							apache2_variables.append(key+' ' +value)

			for valc in params:        
				for val in apache2_variables:
					if val in valc:
						print colored('[INFO] Value OK: ' + val,self.cok,attrs=['bold'])
						apache2_variables_ok.append(val)
					else:               
						apache2_variables_nok.append(val)

			resulting_list = list(set(apache2_variables_nok) - set(apache2_variables_ok))

			for val in resulting_list:      
				if re.sub(r'#.*$','',val):
					print colored('[WARN] Value not match, commented or not include in filters: ' + val,self.cwarning,attrs=['bold'])
			


		except IOError:
			print colored('[ERROR] filepath not found, check config value: apache2_path=' + filepath, self.cwarning,attrs=['bold'] )
			return ''
			
