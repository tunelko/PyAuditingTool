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
from modules.template_module import template_module
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
		self.atdatetime = str(datetime.date(datetime.now())) + '_at_' + str(self.current_time())

		self.cwarning = 'red'
		self.cinfo = 'blue'	
		self.calert = 'yellow'
		self.cok = 'green'
		self.cdefault = 'green' 
		self.symalert = '**' 
		self.path = ''
		self.compare_md5_file = 'tmp_md5_compare_packages.txt'
		self.tmppath = self.path[:1].replace('/','') + self.path[1:]
		self.cmd = 'cat /var/lib/dpkg/info/*.md5sums|grep -E "^[0-9a-f]{32}  ' + self.tmppath + '" > data/tmp_md5_compare_packages.txt'

		#paths 
		self.data_path = 'data/'
		self.reports_path = 'reports/'
		# be sure to be root  
		self.check_requirements()
		# report name  
		self.report_name = 'tmp_report_' + self.atdatetime + '.txt' 
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
		def run_only(option):
			#global_info, users, services, stat, integrity
			if option[0] == 'info':				
				print colored(self.banner, self.cok)
				start = timeit.default_timer()
				self.separator()
				self.global_info()
				stop = timeit.default_timer()
				total_time = stop - start				
				print colored('[INFO] '+ self.current_time() + ' (' + option[0] +') running checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])					
				self.separator()
				exit(0)

			elif option[0] == 'users':
				print colored(self.banner, self.cok)
				# call to check_users part
				start = timeit.default_timer()				
				self.check_users()
				stop = timeit.default_timer()
				total_time = stop - start
				self.separator()
				print colored('[INFO] '+ self.current_time() + ' (' + option[0] +') checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])
				self.separator()
				exit(0)
				
			elif option[0] == 'services':
				print colored(self.banner, self.cok)
				start = timeit.default_timer()				
				self.check_services()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' (' + option[0] +') checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])
				self.separator()
				exit(0)
				
			elif option[0] == 'integrity' and len(option) == 1:
				print colored(self.banner, self.cok)				
				start = timeit.default_timer()				
				self.check_integrity_packages()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' (' + option[0] +') checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])
				self.separator()
				exit(0)

			elif option[0] == 'integrity' and option[1] == 'local_compare':
				print colored(self.banner, self.cok)				
				start = timeit.default_timer()				
				self.check_integrity()
				stop = timeit.default_timer()
				total_time = stop - start
				print colored('[INFO] '+ self.current_time() + ' (' + option[0] +') checks take ' +  str(total_time) + ' seconds to complete ', self.cinfo, attrs=['bold'])
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
			if args.get_updates:
			    self.get_updates()
			    exit(0)

		### Main
		if __name__ == '__main__':
		    parser = argparse.ArgumentParser(description='PyAuditingTool: A tool to test GNU/Linux security and configuration !')
		    parser.add_argument("-v", "--version", action='version', help="show version", version=__version__ +' by ' + __author__)
		    parser.add_argument("-c", "--create-report", action='store_true', dest='create_report', help="create report (default HTML format)")
		    parser.add_argument("-f", "--format", nargs='+',dest='set_format', help="Available report formats: HTML(default), CSV, XML, TXT")		    
		    parser.add_argument("-ro", "--run-only", nargs='+',dest='run_only', help="Run only a check: 'info', 'users', 'services', 'integrity [local_compare]'")
		    parser.add_argument("-ca", "--cache",action='store_true', help="Do not start over again, get cached data")
		    parser.add_argument("-ff", "--flush",action='store_true',dest='remove_data', help="Delete any previous data")
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

    def global_info(self):
			global_info = platform_module('global_info')
			self.separator()
			print colored('[TASK] '+ self.current_time() + ' Global system info',self.cinfo, attrs=['bold'])
			self.separator()
			print colored(global_info.get_platform(), self.cinfo) 
			print colored(global_info.get_dist(), self.cinfo)
			print colored(global_info.get_arquitecture(), self.cinfo)
			self.separator()	
			#self.save_html('mytemplate.html', data='report data here')			


    def check_users(self):
    	# config & class loading
		users = users_module('users')
		sudoers = self.cfg.get_sudoers_path()
		number_of_commands_per_user = self.cfg.get_number_of_commands_per_user()

		print users.separator()
		print colored('[TASK] '+ self.current_time() + ' Enumerating users with login access & group id 0',self.cinfo, attrs=['bold'])
		print users.get_enum_usergroups(number_of_commands_per_user)						
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
		services.check_heartbleed()		
		services.check_services(sshd_path, params)


		# Apache2 confguration 
		apache2_path = self.cfg.get_apache2_path()
		params = self.cfg.get_apache2_variables2check().split(':')
		self.separator()
		print colored('[TASK] '+ self.current_time() + ' Checking Apache2 configuration '+ apache2_path ,self.cinfo, attrs=['bold'])
		self.separator()
		services.check_services(apache2_path, params)
		self.separator()

		# Sysclt confguration 
		sysctl_path = self.cfg.get_sysctl_path()
		params = self.cfg.get_sysctl_variables2check().split(':')		
		
		print colored('[TASK] '+ self.current_time() + ' Checking sysctl configuration '+ sysctl_path ,self.cinfo, attrs=['bold'])
		self.separator()
		services.check_services(sysctl_path, params,delimiter=' = ')
		self.separator()


		return ''


		# Check integrity against first comparation running (on each path)
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
				print colored('[TASK] '+ self.current_time() + ' md5sum for integrity on ' + path ,self.cinfo, attrs=['bold'])
				print integrity.get_md5sum(path)	

			for path in integrity_paths:
				tmppart = re.sub('/','_',path)
				self.separator()	
				print colored('[TASK] '+ self.current_time() + ' Verifying integrity on ' + path, self.cinfo, attrs=['bold'])	
				self.separator()					
				integrity.compare_checksums(self.data_path + 'tmp_md5'+tmppart+'.txt', self.data_path + 'tmp_md5_compare'+tmppart+'.txt', delimiter='  ')

			return ''


			# Check integrity on system md5sums path 
    def check_integrity_packages(self):
			# call module 
			integrity = integrity_module('integrity')
			# task: integrity of binaries defined in config 
			integrity_paths = self.cfg.get_integrity_paths().split(':')
			md5pakages_paths = self.cfg.get_md5packages_paths()

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
				print colored('[TASK] '+ self.current_time() + ' checking md5sums PACKAGES MODE   ' + path ,self.cinfo, attrs=['bold'])
				print integrity.get_md5sum(path)	

			for path in integrity_paths: 	
				tmppart = re.sub('/','_',path)
				compare_md5_file = 'tmp_md5_compare_packages.txt'
				tmppath = path[:1].replace('/','') + path[1:]
				cmd = 'cat '+md5pakages_paths+'*.md5sums|grep -E "^[0-9a-f]{32}  ' + tmppath + '" > data/tmp_md5_compare_packages.txt'
				self.separator()	
				print colored('[TASK] '+ self.current_time() + ' Verifying integrity on ' + path, self.cinfo, attrs=['bold'])	
				self.separator()	
				print colored('[CMD] Executing:' + cmd , self.cok, attrs=['dark']) 
				os.system(cmd)
				integrity.compare_checksums(self.data_path + 'tmp_md5'+tmppart+'.txt', self.data_path + compare_md5_file, delimiter='  ')	


			return ''			

		# Update via Github
    def get_updates(self): 
			return os.system('git pull')

	# Save data for reports 
    def save_data(self, report, data):
		with open(report, 'a') as f:
			f.write(data+'\n')
			f.close 

	# Delete integrity data
    def remove_data(self):
			ask = raw_input(colored('Do you want to DELETE integrity data? [Y]/[n]: ', self.cwarning, attrs=['bold']))
			if ask == '' or ask == 'y' or ask == 'Y':
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

    def save_html(self, template_file, data):
		#HTML5 templating Jinja2 system 
		template = template_module('template')
		output = template.print_html_doc(template_file, data)
		# to save the results
		with open(self.reports_path + 'report_'+self.atdatetime+'.html', 'wb') as f:
			f.write(output)
		

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

# task: Check integrity on binaries via config.cfg (default: md5sums packages)
obj.check_integrity_packages()

obj.separator()	
stop = timeit.default_timer()
total_time = stop - start
print colored('[INFO] '+ obj.current_time() + ' All running checks take ' +  str(total_time) + ' seconds to complete ', obj.cinfo, attrs=['bold'])	
obj.separator()	
