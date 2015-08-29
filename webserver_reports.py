#!/usr/bin/env/python
# -*- coding: utf-8 -*-
# Web server class
import tornado.web          # the Tornado web framework
import tornado.httpserver   # the Tornado web server
import tornado.ioloop       # the Tornado event-loop


class webserver_reports(tornado.web.RequestHandler):
    def get(self):
		# renders the Tornado template
        self.render('report_template.html', user='Admin', title='Reports')

# prepares the application
app = tornado.web.Application([
        (r"/", webserver_reports),
    ], debug=True, template_path='templates')

def start_server():
    srv = tornado.httpserver.HTTPServer(app, xheaders=True)
    # listens incoming request on port 8000
    srv.bind(8888, '')
    # starts the server using 1 process
    # unless you know what you're doing, always set to 1
    srv.start(1)
    # runs all the things
    tornado.ioloop.IOLoop.instance().start()

def stop_server():
    tornado.ioloop.IOLoop.instance().stop()

if __name__ == "__main__":
    import time, threading
    threading.Thread(target=start_server).start()
    print "Your web server will self destruct in 5 seconds"
    time.sleep(5)
    stop_server()



