#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import traceback
import copy
import socket
import json


class Splunk(object):

    def __init__(self, connect_string):

        self.protocol, self.host, self.port = connect_string.split(":")

    def push(self, data):
        for u in self.unwind(data):
            getattr(self, self.protocol)(u)

    def unwind(self, data):
        """

        """
        if isinstance(data['data'], list):
            contents = data.pop('data')
            for c in contents:
                _t = data
                _t['data'] = c
                yield _t

        elif isinstance(data['data'], dict):
            yield data

        else:
            yield data

    def tcp(self, data):
        """

        """

        try:
            set_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_sock.connect((self.host, int(self.port)))
            ss = (json.dumps(data) + '\n').encode('raw-unicode-escape')
            try:
                set_sock.send(ss)
            except (AttributeError, socket.error) as e:
                pass
            set_sock.close()
            return True
        except socket.error as e:
            print("socket connect error: %s" % str(e))
            return False
