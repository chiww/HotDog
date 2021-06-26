#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
author：  chiweiwei@sfmail.sf-express.com
收集信息
"""
from __future__ import absolute_import
from __future__ import print_function

import os
import platform
import time
import re
import traceback
import sys
import base64


class Collect(object):

    def __init__(self, rules: list):
        self.hostname = platform.node()
        self.version = platform.platform()
        self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.rules = rules

        try:
            self._check_rule_validity()
        except Exception as e:
            print(e)
            sys.exit(1)

        self.host = self.host_info()
        self.task_id = "{timestamp}_{hostname}".format(**self.host)

    @staticmethod
    def host_info():
        """
        获取基本系统信息
        :return:
        """

        def get_ips():
            _ips = []
            for i in os.popen('ip address').read().splitlines():
                _ips.extend(re.findall(r'\s+inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', i))

            return _ips

        info = dict()
        info['hostname'] = platform.node()
        info['system'] = platform.platform()
        info['datetime'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        info['timestamp'] = int(time.time())
        info['ips'] = get_ips()
        return info

    def _check_rule_validity(self):
        """
        检查规则是否合法
        :return:
        """

        assert isinstance(self.rules, list), "Rules must be type <list>."
        for rule in self.rules:
            assert "id" in rule.keys(), "Miss <id> in rule, please check rule. rule: %s" % str(rule)
            assert "name" in rule.keys(), "Miss <name> in rule, please check rule. rule: %s" % str(rule)
            assert "category" in rule.keys(), "Miss <category> in rule, please check rule. rule: %s" % str(rule)
            assert "source" in rule.keys(), "Miss <source> in rule, please check rule. rule: %s" % str(rule)
            assert isinstance(rule['source'], dict), "<source> field must be <dict>, please check."
            assert "action" in rule['source'].keys(), "Miss <source> in rule[source], please check rule. rule: %s" % str(rule)
            assert isinstance(rule['source']['action'], dict), "<action> field must be <dict>, please check."
            assert "method" in rule['source']['action'].keys(), "Miss <method> in rule[source], " \
                                                                "please check rule. rule: %s" % str(rule)
            assert "from" in rule['source']['action'].keys(), "Miss <from> in rule, " \
                                                              "please check rule. rule: %s" % str(rule)

            if rule['source']['action']['method'] == "stdout":
                assert not self._is_danger_cmd(rule['source']['action']['from']), "Rule: %s contain danger command, " \
                                                                                  "illegal and would not run!" % str(rule)

            # TODO:
            # 1. upload
            # 2. parser

    @staticmethod
    def _is_danger_cmd(command):
        """
        排除命令行中高危命令执行
        :param command:
        :return:
        """
        danger_exe = ['reboot', 'shutdown', 'halt', 'du', 'bash',
                      'python', 'php', 'java', 'perl'
                      'vim', 'sudo', 'su']

        for exe in danger_exe:
            if exe in command:
                return True

        return False

    @staticmethod
    def _is_match(string, regex):
        """
        简单正则匹配
        :param string:
        :param regex:
        :return: <bool>
        """

        if not regex:
            return True
        if re.match(regex, string, re.I):
            return True
        return False

    def stdout(self, command: str, filter_re: str = None):
        """
        输出原始命令行结果
        :param command
        :param filter_re
        :return:
            {'from': <command>, 'content': <result>, 'filter_re': }
        """
        if self._is_danger_cmd(command):
            print("Error: <%s> contain danger command, can not run, please check!" % command)
            return ""
        p = os.popen("%s 2>/dev/null" % command)
        return [{'from': command, 'content': base64.b64encode(p.read().encode('utf-8')).decode('utf-8')}]

    @staticmethod
    def filestrings(file, filter_re: str = None):
        """
        原始文件strings
        :param file:
        :param filter_re
        :return:
        """

        def _get(_f):
            if os.path.exists(_f):
                print("strings %s 2>/dev/null" % (_f + _grep))
                p = os.popen("strings %s 2>/dev/null" % (_f + _grep))
                _stdout = p.read().encode('utf-8')
            else:
                _stdout = "No such file".encode('utf-8')
            return _stdout

        # 使用grep过滤匹配的字符串
        if filter_re:
            _grep = "| sed '%s'" % filter_re
        else:
            _grep = ""

        if isinstance(file, list):
            result = []
            for f in file:
                if isinstance(f, dict) and 'from' in f:
                    file_path = f['from']
                else:
                    file_path = f
                result.append({'from': file_path, 'content': base64.b64encode(_get(file_path)).decode('utf-8')})
        elif isinstance(file, str):
            result = [{'from': file, 'content': base64.b64encode(_get(file)).decode('utf-8')}]
        else:
            result = [{'from': file, 'content': ''}]
            print('Error: error type in filestrings args[0]')
        return result

    def filewalk(self, directory: str, filter_re: str = None):
        """
        遍历目录或者文件，获取文件路径
        :param directory:
        :param filter_re:
        :return:
        """

        def walk(path):
            if os.path.isdir(path):
                for f in os.listdir(path):
                    p = os.path.join(path, f)
                    if not os.path.exists(p):
                        continue
                    if self._is_match(p, '^/proc/self.*'):
                        continue
                    if self._is_match(p, '^/proc/\d+/cwd.*'):
                        continue
                    if self._is_match(p, '^/proc/\d+/task.*'):
                        continue
                    if self._is_match(p, '^/proc/\d+/root.*'):
                        continue
                    for ff in walk(p):
                        yield ff
            else:
                yield path

        result = []

        for file in walk(directory):
            if os.path.exists(file) and self._is_match(file, filter_re):
                try:
                    result.append({'from': file, 'content': os.readlink(file)})
                except OSError as e:
                    result.append({'from': file, 'content': file})
                # result.append({'from': file, 'content': file})
        return result

    def filestats(self, path: list, filter_re: str = None):
        """
        获取文件状态值
        :param path:   [{'from': '/etc/passwd', 'content': '/etc/passwd'}]
        :param filter_re
        :return:
        """
        try:
            data = []
            for p in path:
                if not os.path.exists(p['content']):
                    continue
                try:
                    st = {'from': p['from'], 'content': ''}
                    _stat = os.stat(p['content'])
                    st['content'] = _stat.__repr__()
                    data.append(st)
                except Exception as e:
                    print(p)
                    print(e)
            return data
        except Exception as e:
            print(e)

    def run(self):

        for rule in self.rules:
            # 初始化
            data = dict()
            data['rule_id'] = rule['id']
            data['name'] = rule['name']
            data['category'] = rule['category']
            data['host'] = self.host
            data['source'] = rule['source']
            data['parser'] = rule.get('parser', None)
            data['task_id'] = self.task_id
            data['data'] = None
            action = rule['source']['action']
            formater = rule['source'].get('format', None)

            try:
                raw = getattr(self, action['method'])(action['from'], filter_re=action.get('filter', None))
                if formater:
                    output = getattr(self, formater['method'])(raw, filter_re=formater.get('filter', None))
                    if output:
                        data['data'] = output
                else:
                    data['data'] = raw
            except Exception as e:
                print(rule, str(e))
                traceback.print_exc()

            yield rule, data


if __name__ == '__main__':

    import pprint

    def test_stdout():
        c = Collect([{
            "id": "C0001",
            "name": "进程状态",
            "description": "获取进程状态信息",
            "category": "user",
            "source": {
                "action": {"method": "stdout", "from": "shutdown"},
                # "format": {"method": "readlines"}
            }
        }])
        print(c.run()[0])

    def test_filestrings():
        c = Collect([{
            "id": "C0001",
            "name": "账号信息",
            "description": "获取/etc/passwd信息",
            "category": "user",
            "source": {
                "action": {"method": "filestrings", "from": "/etc/passwd"},
                "format": {"method": "readlines"}
            }
        }])
        print(c.run()[0])

    def test_filewalk():
        c = Collect([{
            "id": "C0001",
            "name": "进程执行文件",
            "description": "获取/proc/*/exe信息",
            "category": "user",
            "source": {
                "action": {"method": "filewalk", "from": "/proc", "filter": "/proc/\d+/exe"},
                "format": {"method": "filestats"}
            }
        }])
        pprint.pprint(c.run()[0])


    test_stdout()
    #test_filestrings()
    # test_filewalk()

