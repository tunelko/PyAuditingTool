# -*- coding: utf-8 -*-
'''
Created on June 30, 2014
@author: @tunelko
'''

import os, re 
import spwd, pwd, grp 
from datetime import datetime
from termcolor import colored
import commands

class users_module(object):
    ''' Class that handles any user-controlled settings '''

    # Feature enable/disable
    _integrity_check_dirs = None

    def __init__(self, cfg_file='config.cfg'):
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
        # report name  
        self.report_name = 'tmp_report_' + str(datetime.date(datetime.now())) + '__' + str(self.current_time()) + '.txt' # raw_input(colored("Enter report name: ", self.cinfo, attrs=['bold']))
        # global config 

    # Dummy separator 
    def separator(self,attrs=''): 
        print colored('='*99, self.cinfo,attrs='') 
        return ''
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
                gid = lines[4]
                #print 'Effective User ID is', pwd.getpwuid(int(uid))[0]
                shell = re.sub('\n','',lines[6])
                group = grp.getgrgid(uid)[0]
                os.system('grep -e "^'+username+'" /etc/passwd | awk -F: {\'print $6\'}>>tmp_cmds.txt')

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

                
            #last 10 cmds per user 
            with open('tmp_cmds.txt','r') as tmp:
                for entry in tmp:
                    history = re.sub('\n','',entry+'/.bash_history')
                    if os.path.isfile(history): 
                        print self.separator()
                        print colored('[INFO] Last commands for user '+entry, self.cinfo,attrs=['bold'])
                        print self.separator()
                        os.system('head -n20 '+history+'|cat -n')

            # print 'resume:' , users_login_access
            os.remove('tmp_cmds.txt')
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
