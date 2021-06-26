#!/usr/bin/env bash

cd /tmp;
curl -o endpoint.tar.gz http://172.16.1.60:5566/endpoint.tar.gz;
tar -xzvf endpoint.tar.gz && rm -rf endpoint.tar;
python3 endpoint/main.py;
