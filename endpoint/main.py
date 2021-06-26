#!/usr/bin/python

import sys
import os
import json
from collect import Collect
from upload import Upload
from rule import load_rule

upload = Upload()
upload_target = '172.16.1.60:5566'

PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_PATH)

DEFAULT_RULE_PATH = "/endpoint/rule/BASE.yml"


def collect(rules=''):
    """
    USAGE: rules = [
        {
            "id": "C0015",
            "name": "nginx",
            "description": "nginx",
            "category": "process",
            "source":{
                "action":{
                    "method":"stdout",
                    "from": "ps -efwww"
                }
            }
        }
    ]
    :param rules:
    :return:
    """

    rule_file = os.path.dirname(os.path.abspath(PROJECT_PATH)) + DEFAULT_RULE_PATH
    if rules == '' or rules == "[]":
        rules = []

    if not rules:
        rules = load_rule(rule_file)
    else:
        try:
            rules = json.loads(rules)
        except Exception as e:
            return 1, "rules非json格式，请校验; Error: %s  输入的内容是: %s" % (str(e), str(rules))

    c = Collect(rules)
    result = list()
    for rule, data in c.run():
        upload.post(data, target=upload_target)
        result.append({'rule': rule})
    return 0, result


if __name__ == '__main__':

    ru = [
        {'id': 'C0037',
         'name': '进程执行文件状态',
         'description': '获取/proc/*/exe文件状态',
         'category': 'sysenv',
         'source': {
             "action": {"method": "filewalk", "from": "/proc", "filter": "/proc/\d+/exe"},
         },
         'parser': {'name': 'foo', 'args': '', 'kwargs': ''}
         # 'upload': {'method': 'tcp', 'uri': 'tcp:127.0.0.1:1516'}
         }]

    print(collect())



