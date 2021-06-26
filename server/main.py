# -*- coding:utf-8 -*-
from __future__ import absolute_import
from __future__ import print_function

import argparse
import traceback
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import sys
import io
import json
import os

PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_PATH)

from parser import Parser
from forward import Splunk

splunk_connect = "tcp:127.0.0.1:2021"


def update_endpoint():

    os.system('rm -rf endpoint.tar.gz')
    os.popen('tar -zcf endpoint.tar.gz ../endpoint')
    print("Update endpoint.tar.gz success!")


def handler(host, data):
    data['host']['ip'] = host[0]
    p = data['parser']

    if not p:
        p = {'method': 'common', 'args': [], 'kwargs': {}}
        data['parser'] = p

    try:
        parser_data = Parser().run(data, p['method'], *p.get('args', []), **p.get('kwargs', {}))
        print(parser_data['rule_id'], parser_data['name'], type(parser_data['data']), str(parser_data['source']),
              len(parser_data['data']))
        Splunk(splunk_connect).push(parser_data)

    except Exception as e:
        print(traceback.format_exc())


class HotDogHandler(SimpleHTTPRequestHandler):

    def do_POST(self):

        try:
            _length = int(self.headers['Content-Length'])
            _data = self.rfile.read(_length)
            data = _data.decode('utf-8')
        except Exception as e:
            data = json.dumps({'error': traceback.format_exc()})

        handler(self.client_address, json.loads(data))

        self.send_response(200)
        self.send_header('Content-Type',
                         'application/json; charset=utf-8')
        self.end_headers()
        out = io.TextIOWrapper(
            self.wfile,
            encoding='utf-8',
            line_buffering=False,
            write_through=True,
        )
        out.write(data)
        out.detach()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """在一个新的线程中处理请求。"""


def run(HandlerClass=HotDogHandler,
        ServerClass=ThreadedHTTPServer, protocol="HTTP/1.0", port=8000, bind=""):
    """Test the HTTP request handler class.

    This runs an HTTP server on port 8000 (or the port argument).

    """
    server_address = (bind, port)

    HandlerClass.protocol_version = protocol
    with ServerClass(server_address, HandlerClass) as httpd:
        sa = httpd.socket.getsockname()
        serve_message = "HotDog Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
        print(serve_message.format(host=sa[0], port=sa[1]))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")
            sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', '-b', default='', metavar='ADDRESS',
                        help='Specify alternate bind address '
                             '[default: all interfaces]')
    parser.add_argument('port', action='store',
                        default=5566, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
    args = parser.parse_args()
    update_endpoint()
    run(HandlerClass=HotDogHandler, port=args.port, bind=args.bind)
