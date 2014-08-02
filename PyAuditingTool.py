#!/usr/bin/python
# -*- coding: utf-8 -*-

""" PyAuditingTool.py:
    Class to check linux server's security and its misconfiguration
"""

__author__ = "@tunelko"
__version__ = 'PyAuditingTool v0.2'

import os, re 
from datetime import datetime
from termcolor import colored
import argparse
import timeit

from modules.users_module import users_module
from modules.services_module import services_module
from modules.platform_module import platform_module
from libs.config_manager import config_manager

class PyAuditingTool(object): 

    def __init__(self):
		self.banner = '''
██████╗ ██╗   ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗███╗   ██╗ ██████╗████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗╚██╗ ██╔╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██║████╗  ██║██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██████╔╝ ╚████╔╝ ███████║██║   ██║██║  ██║██║   ██║   ██║██╔██╗ ██║██║  ███╗  ██║   ██║   ██║██║   ██║██║     
██╔═══╝   ╚██╔╝  ██╔══██║██║   ██║██║  ██║██║   ██║   ██║██║╚██╗██║██║   ██║  ██║   ██║   ██║██║   ██║██║     
██║        ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██║██║ ╚████║╚██████╔╝  ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
[*] by @tunelko                                                                                                                     
        '''
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
		self.md5line = re.compile(r"^(\\?)([0-9a-f]{32}) [\ \*](.*)$")
		#paths 
		self.data_path = 'data/'
		self.reports_path = 'reports/'
		# be sure to be root  
		self.check_requirements()
		# report name  
		self.report_name = 'tmp_report_' + str(datetime.date(datetime.now())) + '__' + str(self.current_time()) + '.txt' # raw_input(colored("Enter report name: ", self.cinfo, attrs=['bold']))
		# global config 
		self.cfg = config_manager('config.cfg')
		
		# Call to create report with format
		def set_format(format):

			if format[0] == 'XML':
				print format[0]
			elif format[0] == 'CSV':
				print format[0]
			elif format[0] == 'TXT':
				print format[0]
			else:
				print colored("Unknown format, need a valid format --h for help\n", self.cwarning,  attrs=['bold'])
				exit(0)

		# Call to run a check 
		def run_only(format):
			#global_info, users, services, stat, integrity
			if format[0] == 'global_info':
				self.global_info()
				exit(0)

			elif format[0] == 'users':
				# call to check_users part
				self.check_users()
				exit(0)
				
			elif format[0] == 'services':
				self.check_services()
				exit(0)
				
			elif format[0] == 'integrity':
				print format[0]
			else:
				print colored("Unknown format, need a valid format --h for help\n", self.cwarning,  attrs=['bold'])
				exit(0)

		

		# Parse arguments and call actions
		def main(args):
			''' Call functions in the correct order based on CLI params '''
			# Create report 
			if args.create_report:
			    create_report()

			# Specify report's format
			if args.set_format is not None:
			    set_format(args.set_format)

			# Specify only to run a check
			if args.run_only is not None:
			    run_only(args.run_only)
			    
			# Get updates from URL 
			if args.get_updates:
			    get_updates()

		### Main
		if __name__ == '__main__':
		    parser = argparse.ArgumentParser(description='PyAuditingTool: A tool to test GNU/Linux security and configuration !')
		    parser.add_argument("-v", "--version", action='version', help="show version", version=__version__ +' by ' + __author__)
		    parser.add_argument("-c", "--create-report", action='store_true', dest='create_report', help="create report (default HTML format)")
		    parser.add_argument("-f", "--format", nargs='+',dest='set_format', help="Available report formats: HTML(default), CSV, XML, TXT")		    
		    parser.add_argument("-ro", "--run-only", nargs='+',dest='run_only', help="Run only a check: global_info, users, services, integrity")
		    parser.add_argument("-ca", "--cache",action='store_true', help="Do not start over again, get cached data")
		    parser.add_argument("-u", "--update", action='store_true', dest='get_updates', help="Update to the last version of PyAuditingTool")
		    main(parser.parse_args())

	# Check requirements before run 
    def check_requirements(self):
    	if os.geteuid() != 0:
			exit(colored("-- [INFO] -- You need to be root to run this script. Exiting ... \n", self.cwarning, attrs=['bold']))

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


    	print colored('[CMD] Executing: for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do md5sum -b '+path+'/$file; done > ' + tmpf, self.cok, attrs=['dark']) 
    	os.system('for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do md5sum -b '+path+'/$file; done > ' + tmpf )
    	return ''

		# os.system('cat tmp_md5' + re.sub('/','_',path) + '.txt')


	# Compare md5 checksums on two lists of md5 (old,new)
    def compare_checksums(self, file1, file2):
	try:

		# First time running the script -- need ask for re-run 
		if not os.path.isfile(file2):
			print colored('[INFO] First time running script or tmp files NOT found. Please, re-run this script. ',self.cinfo, attrs=['bold'])
			ask = raw_input(colored('Do you want to restart it now? [Y]/[n]: ', self.cwarning, attrs=['bold']))
			if ask == '': 
				os.system('./PyAuditingTool.py')
			else:
				print colored('Bye ... !\n',self.calert, attrs=['dark'])
				exit(0)


		with open(file1, 'r') as f:
			for line in f:
				hash1 =  line.split('*')
				filename1 = re.sub('\n','',hash1[1])
				match = self.md5line.match(hash1[0])

				with open(file2, 'r') as f2:
					for line2 in f2:
						hash2 =  line2.split('*')
						filename2 = re.sub('\n','',hash2[1])

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

	# Check stat on binaries (via config)
    def get_stat_files(self, path): 
	print colored('[CMD] Executing: for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do stat -c "UID: %u (%U)- GID: %g (%G) %n" '+path+'/$file; done > tmp_stat.txt', self.cok, attrs=['dark'])
	os.system('for file in `find '+path+'/ -maxdepth 1 -type f -printf "%f\n"`; do stat -c "UID: %u (%U)- GID: %g (%G) %n" '+path+'/$file; done > tmp_stat.txt')
	try: 
		with open('tmp_stat.txt', 'r') as f:
			for line in f:
				line = re.sub('\n','',line)
				print colored(line,self.cinfo,attrs=['bold'])

	except IOError:
		print colored('[ERROR] File not found, check config value: sudoers_path=' + file, self.cwarning,attrs=['bold'] )
	return ''




    def check_users(self):
    	# config & class loading
		users = users_module('users')
		sudoers = self.cfg.get_sudoers_path()

		print users.separator()
		print colored('[TASK] '+ self.current_time() + ' Enumerating users with login access & group id 0',self.cinfo, attrs=['bold'])
		print users.get_enum_usergroups()				
		print users.separator()		
		print colored('[TASK] '+ self.current_time() + ' Enumerating system users and password policy ',self.cinfo, attrs=['bold'])
		print users.get_policy_usergroups()		
		print colored('[TASK] '+ self.current_time() + ' Getting users in ' + sudoers ,self.cinfo, attrs=['bold'])
		print users.separator()
		print users.get_sudoers(sudoers)
		print colored('[INFO] '+ self.current_time() + ' Check if the users above are right to be in ' + sudoers ,self.cwarning, attrs=['bold'])
		return''





    def check_services(self):
    	# config & class loading 
		services = services_module('services')
		sshd_path = self.cfg.get_sshd_path()		
		params = self.cfg.get_sshd_variables2check().split(':')

		# SSH confgurations check 
		self.separator()
		print colored('[TASK] '+ self.current_time() + ' Checking SSH configuration '+ sshd_path ,self.cinfo, attrs=['bold'])
		self.separator()
		services.check_sshd(sshd_path, params)

		# Apache2 confguration 
		apache2_path = self.cfg.get_apache2_path()
		params = self.cfg.get_apache2_variables2check().split(':')
		self.separator()
		print colored('[TASK] '+ self.current_time() + ' Checking Apache2 configuration '+ apache2_path ,self.cinfo, attrs=['bold'])
		self.separator()
		services.check_apache2(apache2_path, params)
		print self.separator()
		return ''


    def global_info(self):
			global_info = platform_module('global_info')
			self.separator()
			print colored('[TASK] '+ self.current_time() + ' Global system info',self.cinfo, attrs=['bold'])
			self.separator()
			print colored(global_info.get_platform(), self.cinfo) 
			print colored(global_info.get_dist(), self.cinfo)
			print colored(global_info.get_arquitecture(), self.cinfo)





	# Save data for reports 
    def save_data(self, report, data): 

		with open(report, 'a') as f:
			f.write(data+'\n')
			f.close 


# Init object and start. 
obj = PyAuditingTool()
start = timeit.default_timer()
print colored(obj.banner, obj.cok) 
print '[INIT]' , obj.current_time() , '[*] Report file: ', obj.report_name

# task: global info: platform , dist 
obj.global_info()

# task: check users part 
obj.check_users()

# task: Check sshd confguration 
obj.check_services()




# task: check stat of files (sid,gid,owner,groupowner) defined in config.cfg  
stat_paths = obj.cfg.get_stat_paths().split(':')
for path in stat_paths: 	
	obj.separator()
	print colored('[TASK] '+ obj.current_time() + ' Making stat on files (sid,gid,owner,groupowner) ' + path ,obj.cdefault, attrs=['bold'])
	print obj.get_stat_files(path)	
	print colored('[INFO] '+ obj.current_time() + ' Remember to check manually on the report ', obj.cwarning, attrs=['bold'])



# task: integrity of binaries defined in config 
integrity_paths = obj.cfg.get_integrity_paths().split(':')

for path in integrity_paths: 
	tmppart = re.sub('/','_',path)
	obj.separator()
	print colored('[TASK] '+ obj.current_time() + ' writing md5sum for integrity on ' + path ,obj.cinfo, attrs=['bold'])
	print obj.get_md5sum(path)	

for path in integrity_paths: 	
	tmppart = re.sub('/','_',path)
	obj.separator()	
	print colored('[TASK] '+ obj.current_time() + ' Verifying integrity on ' + path, obj.cinfo, attrs=['bold'])	
	obj.separator()	
	obj.compare_checksums(obj.data_path + 'tmp_md5'+tmppart+'.txt', obj.data_path + 'tmp_md5_compare'+tmppart+'.txt')

	
obj.separator()	
stop = timeit.default_timer()
total_time = stop - start
print colored('[INFO] '+ obj.current_time() + ' All running checks take ' +  str(total_time) + ' seconds to complete ', obj.cinfo, attrs=['bold'])	
obj.separator()	
