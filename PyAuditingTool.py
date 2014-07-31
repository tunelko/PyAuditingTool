#!/usr/bin/python
# -*- coding: utf-8 -*-

""" PyAuditingTool.py:
    Class to check linux server's security and its misconfiguration
"""

__author__ = "@tunelko"
__version__ = 'PyAuditingTool v0.2'

import os, re 
import spwd, pwd, grp 
import platform
from datetime import datetime
from termcolor import colored
import logging as log
import argparse
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

		

		# Parse arguments and call actions
		def main(args):
			''' Call functions in the correct order based on CLI params '''
			# Run unit tests
			if args.run_tests:
			    tests()

			# Create report 
			if args.create_report:
			    create_report()

			# Specify report's format
			if args.set_format is not None:
			    set_format(args.set_format)
			    
			# Get updates from URL 
			if args.get_updates:
			    get_updates()

		### Main
		if __name__ == '__main__':
		    parser = argparse.ArgumentParser(description='PyAuditingTool: A tool to test GNU/Linux security and configuration !')
		    parser.add_argument("-v", "--version", action='version', help="show version", version=__version__ +' by ' + __author__)
		    parser.add_argument("-c", "--create-report", action='store_true', dest='create_report', help="create report (default HTML format)")
		    parser.add_argument("-f", "--format", nargs='+',dest='set_format', help="Available report formats: HTML(default), CSV, XML, TXT")
		    parser.add_argument("-t", "--tests", action='store_true', dest='run_tests',help="run tests (default config)")
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
		
	# get uname() 
    def get_platform(self):
		return platform.uname() 

	# get distribution 
    def get_dist(self):
		return platform.dist() 

	# Call user/groups enum, several users checks  
    def get_enum_usergroups(self):
		users_login_access=[]
		users_grp0=[]

		os.system('cat /etc/passwd > /tmp/tmp_users.txt')
		with open('/tmp/tmp_users.txt','r') as tmp:
			for entry in tmp:
				#print entry
				lines = entry.split(':')
				username=lines[0]
				uid = lines[3]
				print uid
				gid = lines[4]
				#print 'Effective User ID is', pwd.getpwuid(int(uid))[0]
				shell = re.sub('\n','',lines[6])
				group = grp.getgrgid(uid)[0] 

				# list system users with login access 
				if shell != '/bin/false' and  shell != '/usr/sbin/nologin':
					print colored('[INFO] Username with login access: '+username+'('+group+')'+' - please check manually' , self.cwarning,attrs=['bold'])
					users_login_access.append(username)
				else: 
					print colored('[INFO] Username with no shell: '+username +'('+group+')', self.cinfo,attrs=['bold'])


				# Check for user group id 0 
				if uid == '0' and username != 'root': 
					print colored('[INFO] Warning! Check this username group: '+username +'('+group+')', self.cwarning,attrs=['bold'])	
					users_grp0.append(username)				
				else:
					print colored('[INFO] Testing GROUP ID 0 for user: ' + username +'('+group+') Correct! '  , self.cok,attrs=['bold'])
					
				# Check for user group id 0 
				if uid == False and gid == False:
					print colored('[INFO] Warning! Owner and group not found for: '+username +'('+group+')', self.cwarning,attrs=['bold'])	

			# print 'resume:' , users_login_access
			return ''

	# Password policiy checks 
    def get_policy_usergroups(self):
	#initialize lists
	users = []
	groups = []
	#get password & groups 
	users_db = spwd.getspall() 
	group_db = grp.getgrall()
	#print users_db, group_db
	try:
	    #check passwd policiy foreach user
	    for entry in users_db:
			username = entry[0]
			self.separator()
			print colored('[CMD] Executing: chage -l  ' + username , self.calert, attrs=['dark']) 
			os.system('chage -l  ' + username + '> tmp_password_policy.txt')
			os.system('cat tmp_password_policy.txt')
			# self.save_data(self.report_name, os.system('cat tmp_password_policy.txt'))
			#TO-DO: set recommendations 


	except:
	    print "There was a problem running the script."
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

						if hash1[0] == hash2[0]:
							data = '[OK] Hash OK '+hash1[0] +  '| File: ' + filename1 
							self.save_data(self. report_name, data)
							print colored(data, self.cok , attrs=['bold'])							
							
						elif hash1[0] != hash2[0] and filename1 == filename2:
							data = '[WARN] File changed, should be '+hash1[0] +  ' and now is ' + hash2[0] +'| File: ' + filename1
							self.save_data(self. report_name, data)
							print colored(data , self.cwarning , attrs=['bold'])


						

	except IOError, e:		
		print "Error reading checksums file %s: %s" % (file, e)

	# Check SSH config (via config values)
    def check_sshd(self, file):
    	sshd_variables2check = self.cfg.get_sshd_variables2check().split(':')
    	sshd_variables=[]    	
    	sshd_variables_ok=[]
    	sshd_variables_nok=[]
	
	try:
		with open(file, 'r') as f:
			for line in f:
				params =  line.split(' ')
				if len(params)==2:
					key = params[0]
					value = re.sub('\n','',params[1])
					sshd_variables.append(key+' ' +value)

		for valc in sshd_variables2check:		
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

	except IOError:
		print colored('[ERROR] File not found, check config value: ssh2_path=' + file, self.cwarning,attrs=['bold'] )
		return ''

	# Check Apache2 config (via config values)
    def check_apache2(self, file):
    	apache2_variables2check = self.cfg.get_apache2_variables2check().split(':')
    	apache2_variables=[]
    	apache2_variables_ok=[]
    	apache2_variables_nok=[]

	
	try:
		with open(file, 'r') as f:
				for line in f:
					params =  line.split(' ')
					if len(params)==2:
						key = params[0]
						value = re.sub('\n','',params[1])
						apache2_variables.append(key+' ' +value)

		for valc in apache2_variables2check:		
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
		print colored('[ERROR] File not found, check config value: apache2_path=' + file, self.cwarning,attrs=['bold'] )
		return ''


	# Check Sudoers config (via config values)
    def get_sudoers(self, file):    
	try: 
		with open(file, 'r') as f:
				for line in f:
					line = re.sub('\n','',line)
					if re.sub(r'#.*$','',line):						
						print colored(line,self.cinfo,attrs=['bold'])

	except IOError:
		print colored('[ERROR] File not found, check config value: sudoers_path=' + file, self.cwarning,attrs=['bold'] )
	return ''

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

	# Save data for reports 
    def save_data(self, report, data): 

		with open(report, 'a') as f:
			f.write(data+'\n')
			f.close 


# Init object and start. 
obj = PyAuditingTool()

print colored(obj.banner, obj.cok) 
print '[INIT]' , obj.current_time() , '[*] Report file: ', obj.report_name

# task: global info: platform , dist 
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Global system info',obj.cinfo, attrs=['bold'])

obj.separator()
print colored(obj.get_platform(), obj.cinfo) 
print colored(obj.get_dist(), obj.cinfo)

# task: enumerating system users with login access, checks for users with group 0
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Enumerating users with login access & group id 0',obj.cinfo, attrs=['bold'])
obj.separator()
print obj.get_enum_usergroups()

# task: sudoers check 
sudoers = obj.cfg.get_sudoers_path()
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Getting users in ' + sudoers ,obj.cinfo, attrs=['bold'])
obj.separator()
print obj.get_sudoers(sudoers)
print colored('[INFO] '+ obj.current_time() + ' Check if the users above are right to be in ' + sudoers ,obj.cwarning, attrs=['bold'])

# task: check password policy on system users 
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Enumerating system users and password policy ',obj.cinfo, attrs=['bold'])
print obj.get_policy_usergroups()

# task: Check sshd confguration 
sshd_path = obj.cfg.get_sshd_path()
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Checking SSH configuration '+ sshd_path ,obj.cinfo, attrs=['bold'])
obj.separator()
obj.check_sshd(sshd_path)

# task: Check Apache2 confguration 
apache2_path = obj.cfg.get_apache2_path()
obj.separator()
print colored('[TASK] '+ obj.current_time() + ' Checking Apache2 configuration '+ apache2_path ,obj.cinfo, attrs=['bold'])
obj.separator()
obj.check_apache2(apache2_path)

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
	obj.compare_checksums(obj.data_path + 'tmp_md5'+tmppart+'.txt', obj.data_path + 'tmp_md5_compare'+tmppart+'.txt')
	
obj.separator()	
