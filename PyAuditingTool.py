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
from modules.integrity_module import integrity_module
from modules.platform_module import platform_module
from modules.update_module import update_module
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
				start = timeit.default_timer()
				self.separator()
				self.global_info()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' ' + format[0] +'  running checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])					
				self.separator()
				exit(0)

			elif format[0] == 'users':
				# call to check_users part
				start = timeit.default_timer()				
				self.check_users()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' ' + format[0] +'  running checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])					
				self.separator()
				exit(0)
				
			elif format[0] == 'services':
				start = timeit.default_timer()				
				self.check_services()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' ' + format[0] +'  running checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])					
				self.separator()
				exit(0)
				
			elif format[0] == 'integrity':
				start = timeit.default_timer()				
				self.check_integrity()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' ' + format[0] +'  running checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])					
				self.separator()
				exit(0)
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
			if args.remove_data:
			    self.remove_data()
			    exit(0)
			    
			# Get updates from URL 
			if args.update:
			    update = update_module.update(os.path.abspath("."))
			    update.update('.')
			    exit(0)

		### Main
		if __name__ == '__main__':
		    parser = argparse.ArgumentParser(description='PyAuditingTool: A tool to test GNU/Linux security and configuration !')
		    parser.add_argument("-v", "--version", action='version', help="show version", version=__version__ +' by ' + __author__)
		    parser.add_argument("-c", "--create-report", action='store_true', dest='create_report', help="create report (default HTML format)")
		    parser.add_argument("-f", "--format", nargs='+',dest='set_format', help="Available report formats: HTML(default), CSV, XML, TXT")		    
		    parser.add_argument("-ro", "--run-only", nargs='+',dest='run_only', help="Run only a check: global_info, users, services, integrity")
		    parser.add_argument("-ca", "--cache",action='store_true', help="Do not start over again, get cached data")
		    parser.add_argument("-ff", "--flush",action='store_true',dest='remove_data', help="Delete any previous data")
		    parser.add_argument("-u", "--update", action='store_true', dest='update', help="Update to the lastest version of PyAuditingTool")
		    main(parser.parse_args())

	# Check requirements before run 
    def check_requirements(self):
    	if os.geteuid() != 0:
			exit(colored("-- [INFO] -- You need to be root to run this script. Exiting ... \n", self.cwarning, attrs=['bold']))

	# Dummy separator 
    def separator(self,attrs=''): 
		print colored('='*99, self.cinfo,attrs='') 
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
		self.separator()


		return ''


    def global_info(self):
			global_info = platform_module('global_info')
			self.separator()
			print colored('[TASK] '+ self.current_time() + ' Global system info',self.cinfo, attrs=['bold'])
			self.separator()
			print colored(global_info.get_platform(), self.cinfo) 
			print colored(global_info.get_dist(), self.cinfo)
			print colored(global_info.get_arquitecture(), self.cinfo)
			self.separator()	


    def check_integrity(self):
			# call module 
			integrity = integrity_module('integrity')
			# task: integrity of binaries defined in config 
			integrity_paths = self.cfg.get_integrity_paths().split(':')
			# task: check stat of files (sid,gid,owner,groupowner) defined in config.cfg  
			stat_paths = self.cfg.get_stat_paths().split(':')
			for path in stat_paths: 	
				self.separator()
				print colored('[TASK] '+ self.current_time() + ' Making stat on files (sid,gid,owner,groupowner) ' + path ,self.cdefault, attrs=['bold'])
				print integrity.get_stat_files(path)	
				print colored('[INFO] '+ self.current_time() + ' Remember to check manually on the report ', self.cwarning, attrs=['bold'])

			for path in integrity_paths: 
				tmppart = re.sub('/','_',path)
				self.separator()
				print colored('[TASK] '+ self.current_time() + ' writing md5sum for integrity on ' + path ,self.cinfo, attrs=['bold'])
				print integrity.get_md5sum(path)	

			for path in integrity_paths: 	
				tmppart = re.sub('/','_',path)
				self.separator()	
				print colored('[TASK] '+ self.current_time() + ' Verifying integrity on ' + path, self.cinfo, attrs=['bold'])	
				self.separator()	
				integrity.compare_checksums(self.data_path + 'tmp_md5'+tmppart+'.txt', self.data_path + 'tmp_md5_compare'+tmppart+'.txt')

			return ''

		# Update via GitHub
    def get_updates(self): 
			return os.system('git pull')

	# Save data for reports 
    def save_data(self, report, data):
		with open(report, 'a') as f:
			f.write(data+'\n')
			f.close 

	# Delete integrity data
    def remove_data(self):
			ask = raw_input(colored('Do you want to DELETE data? [Y]/[n]: ', self.cwarning, attrs=['bold']))
			if ask == '':
				for the_file in os.listdir(self.data_path):
					file_path = os.path.join(self.data_path, the_file)
					try:
						if os.path.isfile(file_path):
						    os.unlink(file_path)
						    print colored('[INFO] removed ' + file_path + '',self.cinfo,attrs=['bold']) 
					except Exception, e:
						print e
			else:
				print colored('Bye ... !\n',self.calert, attrs=['dark'])
				exit(0)						

		

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

# task: Check integrity on binaries via config.cfg
obj.check_integrity()

obj.separator()	
stop = timeit.default_timer()
total_time = stop - start
print colored('[INFO] '+ obj.current_time() + ' All running checks take ' +  str(total_time) + ' seconds to complete ', obj.cinfo, attrs=['bold'])	
obj.separator()	
