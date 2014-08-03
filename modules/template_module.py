#!/usr/bin/env/python
# 
# Using the file system load
#
# We now assume we have a file in the same dir as this one called
# test_template.html
#

import os,sys
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class template_module(object):
	''' Class that handles HTML ''' 
	def __init__(self, cfg_file='config.cfg'):

		self.current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]

		#paths 
		self.data_path = 'data/'
		self.reports_path = 'reports/'
		self.template_dir = 'templates/'

	def print_html_doc(self, template, data):
			# Create the jinja2 environment.
			j2_env = Environment(loader=FileSystemLoader(self.template_dir),
													 trim_blocks=True)
			return j2_env.get_template(template).render(
					title='Report ' + str(datetime.date(datetime.now())) + '_at_' + str(self.current_time()), 
					block_data=data
			)


