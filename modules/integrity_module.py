#!/usr/bin/python
# -*- coding: utf-8 -*- 
'''
Created on June 30, 2014
@author: @tunelko
'''

import os, re 
import spwd, pwd, grp , time
from datetime import datetime
from termcolor import colored, cprint 
import commands

class integrity_module(object):
		''' Class that handles integrity checks '''

		# Feature enable/disable
		_integrity_check_dirs = None

		def __init__(self, cfg_file='config.cfg'):
				self.current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]
				self.atdatetime = str(datetime.date(datetime.now())) + '_at_' + str(self.current_time())
				self.cwarning = 'red'
				self.cinfo = 'blue' 
				self.calert = 'yellow'
				self.cok = 'green'
				self.cdefault = 'green' 
				self.symalert = '**' 
				self.md5line = re.compile(r"^(\\?)([0-9a-f]{32}) [\ \*](.*)$")
				#paths 
				self.data_path = 'data/'
				self.reports_path = 'reports/'
				# report name  
				self.report_name = 'tmp_report_' + self.atdatetime + '.txt'                
				

		# Dummy separator 
		def separator(self,attrs=''): 
				print colored('='*99, self.cinfo,attrs='') 
				return ''

	# get md5sum -b of any path as param (only files -d)
		def get_md5sum(self,path=''): 
			tmpf = self.data_path + 'tmp_md5' + re.sub('/','_',path) + '.txt'
			#if exists, create compare one for hashing comparation. 
			if os.path.isfile(tmpf): 
				tmpf = self.data_path + 'tmp_md5_compare' + re.sub('/','_',path) + '.txt'
			elif not os.path.isfile(tmpf):
				tmpf = self.data_path + 'tmp_md5' + re.sub('/','_',path) + '.txt'


			print colored('[CMD] Executing: for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do md5sum '+path+'/$file; done > ' + tmpf, self.cok, attrs=['dark']) 
			os.system('for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do md5sum '+path+'/$file; done > ' + tmpf )
			return ''

		# os.system('cat tmp_md5' + re.sub('/','_',path) + '.txt')


	# Compare md5 checksums on two lists of md5 (old,new)
	# whatever integrity or integrity packages. 
		def compare_checksums(self, src, dst, delimiter='  '):
			try:
				# First time running the script -- need ask for re-run 
				if not os.path.isfile(dst):
					print colored('[INFO] First time running script, tmp_md5 files NOT found. Please, re-run this script. ',self.cinfo, attrs=['bold'])
					ask = raw_input(colored('Do you want to restart it now? [Y]/[n]: ', self.cwarning, attrs=['bold']))
					if ask == '': 
						os.system('./PyAuditingTool.py')
					else:
						print colored('Bye ... !\n',self.calert, attrs=['dark'])
						exit(0)

			  # open for reading src
				with open(src, 'r') as f:
					for line in f:
						hash1 =  line.split(delimiter)
						filename1 = re.sub('\n','',hash1[1])						

						with open(dst, 'r') as f2:
							for line2 in f2:								

								hash2 =  line2.split(delimiter)								
								filename2 = re.sub('\n','',hash2[1])
								
								if dst == 'data/tmp_md5_compare_packages.txt':
									 filename2 = '/'+filename2

								#print  hash1[0] ,'==', hash2[0] ,'and', filename1 ,'==', filename2

								if hash1[0] == hash2[0] and filename1 == filename2:
									data = '[OK] Hash OK '+hash1[0] +  '| File: ' + filename1 
									self.save_data(self. report_name, data)
									print colored(data, self.cok , attrs=['bold'])							
									
								elif hash1[0] != hash2[0] and filename1 == filename2:
									data = '[WARN] File changed, should be '+hash1[0] +  ' and now is ' + hash2[0] +'| File: ' + filename1									
									self.save_data(self. report_name, data)
									print colored(data , self.cwarning , attrs=['bold'])

			except IOError, e:		
				print "Error reading checksums file %s: %s" % (file, e)

			#print hash_changed

	# Check stat on binaries (via config)
		def get_stat_files(self, path): 
			print colored('[CMD] Executing: for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do stat -c "UID: %u (%U)- GID: %g (%G) %n" '+path+'/$file; done > tmp_stat.txt', self.cok, attrs=['dark'])
			os.system('for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do stat -c "UID: %u (%U)- GID: %g (%G) %n" '+path+'/$file; done > tmp_stat.txt')
			try: 
				with open('tmp_stat.txt', 'r') as f:
					for line in f:
						line = re.sub('\n','',line)
						files = line.split(' ')
						file = files[6]

						print colored(line,self.cinfo,attrs=['bold'])
						(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)
						#print mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
						print colored("Last modified: %s" % time.ctime(mtime), self.cinfo, attrs=['blink'])
						print colored("Mode: %s" % mode, self.cinfo, attrs=['blink'])
						print colored("Ino: %s" % ino, self.cinfo, attrs=['blink'])
						print colored("Dev: %s" % dev, self.cinfo, attrs=['blink'])
						print colored("Nlink: %s" % nlink, self.cinfo, attrs=['blink'])
						print colored("Size: %s" % size, self.cinfo, attrs=['blink'])
						print colored('-'*99, 'white', attrs=['blink'])



			except IOError:
				print colored('[ERROR] File not found, check config value: sudoers_path=' + file, self.cwarning,attrs=['bold'] )
			return ''


		# Save data for reports 
		def save_data(self, report, data):
			with open(report, 'a') as f:
				f.write(data+'\n')
				f.close 
