#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
author：  chiweiwei@sfmail.sf-express.com
结果上传
"""

import json
import traceback
import socket
import http.client


class Upload(object):

    def syslog(self, body, target):
        """
        syslog 推送
        :param body:
        :param target:
        :return:
        """

        host, port = target.split(":")
        try:
            set_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_sock.connect((host, int(port)))
            ss = (json.dumps(body) + '\n').encode('raw-unicode-escape')
            try:
                set_sock.send(ss)
            except (AttributeError, socket.error) as e:
                pass
            set_sock.close()
        except socket.error as e:
            print("socket connect error: %s" % str(e))
            print(traceback.format_exc())

    def post(self, body, target="127.0.0.1:5566"):
        """

        :param body:
        :param target:
        :return:
        """
        try:
            headers = {'Content-type': 'application/json'}
            conn = http.client.HTTPConnection(target)
            conn.request("POST", "/", json.dumps(body), headers)
            response = conn.getresponse()
            print(response.status, response.reason)
            data1 = response.read()
            print(data1.decode())
        except Exception as e:
            print("post error: %s" % str(e))
            print(traceback.format_exc())


if __name__ == '__main__':

    d = {"a": "1", "b": "2", "c": "3"}
    upload = Upload()
    upload.post(d)




