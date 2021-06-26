#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
采集规则
"""
from __future__ import absolute_import
from __future__ import print_function
import sys
import os

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
package = PROJECT_PATH + '/package'
sys.path.insert(0, package)

from yaml import load
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError as e:
    from yaml import Loader, Dumper


def load_rule(rule_file):
    with open(rule_file, 'r', encoding="utf-8") as yml:
        rule_yaml = load(yml, Loader=Loader)
    return rule_yaml

