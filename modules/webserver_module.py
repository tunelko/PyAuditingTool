#!/usr/bin/env/python
# Web server class


from tornado import netutil
from tornado.web import Application
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.options import options


class webserver_module(tornado.web.RequestHandler):
	''' Class that handles webserver ''' 
	def __init__(self, cfg_file='config.cfg'):
		# Singletons
		self.io_loop = IOLoop.instance()
		self.current_time = lambda: str(datetime.now()).split(' ')[1].split('.')[0]
		self.theme = Theme.by_name(options.default_theme)
