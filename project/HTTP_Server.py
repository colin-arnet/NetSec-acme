from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
from threading import Thread
import ssl
from functools import partial

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

class ShutdownRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if(self.path == '/shutdown'):
            self.server.keep_running = False
            # self.server.shutdown()    
        self.send_response(200)
        self.end_headers()

def start_challenge_server():
    # http server
    print("Start Challenge Server")
    handler = partial(SimpleHTTPRequestHandler, directory='home')
    server = HTTPServer(('', 5002), handler)
    t = Thread(target=server.serve_forever)
    t.start()
    return server

def start_certificate_server():
    # https server
    print("Start Certificate Server")
    keyfile = 'home/.key'
    certfile = 'home/.crt'
    handler = RequestHandler
    server = HTTPServer(('', 5001), RequestHandler)
    server.socket = ssl.wrap_socket(server.socket, keyfile=keyfile, certfile=certfile)
    t = Thread(target=server.serve_forever)
    t.start()
    return server

def start_shutdown_server():
    # http server
    print("Start Shutdown Server")
    handler = ShutdownRequestHandler
    server = HTTPServer(('', 5003), handler)
    server.keep_running = True
    t = Thread(target=server.serve_forever)
    t.start()
    return server

def stop_http_server(server):
    print("Stop HTTP Server")
    server.shutdown()
    server.server_close()