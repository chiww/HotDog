#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
解析与处理
"""
from __future__ import absolute_import
from __future__ import print_function
import os, sys
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_PATH)

import re
import time
from datetime import date, timedelta
import base64
import traceback


class Parser(object):

    def __init__(self):
        """
        work for data, not for stdout.
        """
        self.core = ParserCore()

    def _get_parser_func(self, method):

        try:
            return getattr(self.core, method)
        except Exception as e:
            print("Can not find parser function, use common function!")
            return self.core.common

    def run(self, dataset, method, *args, **kwargs):

        parser_func = self._get_parser_func(method)
        dataset = self._b64decode(dataset)
        kwargs.update({'dataset': dataset})
        result = []
        for data in dataset.pop('data'):
            _from = data['from']
            _content = data['content']
            kwargs.update({'data': data})
            for parser_result in parser_func(_content, *args, **kwargs):
                result.append({'from': _from, 'content': parser_result})
        dataset['data'] = result
        return dataset

    def _b64decode(self, dataset):
        """
        还原数据 base64 decode
        :param dataset:
        :return: <list>
            return example: [{'from': <DATA FROM:string>, 'content': <DETAIL:(string|dict|list)>}]
        """
        if not dataset['data']:
            dataset['data'] = []

        assert isinstance(dataset['data'], list), "data['data'] must be <list>, but <%s>" % type(dataset['data'])

        if self._is_b64encode_by_rule(dataset):
            for data in dataset['data']:
                data['content'] = base64.b64decode(data['content'])
                try:
                    data['content'] = data['content'].decode('utf-8')
                except Exception as e:
                    print(traceback.format_exc())
        return dataset

    @staticmethod
    def _is_b64encode_by_rule(dataset):
        # only stdout and filestrings is the b64encode, so, if then, decode by base64:
        _rule_b64_method = ['stdout', 'filestrings']
        _action_method = dataset['source']['action']['method']
        _format_method = dataset['source'].get('format', {}).get('method', '')
        if _action_method in _rule_b64_method or _format_method in _rule_b64_method:
            return True
        return False


class ParserCore(object):

    @staticmethod
    def common(cmd_stdout, *args, **kwargs):
        return [cmd_stdout]

    def filestats(self, cmd_stdout, *args, **kwargs):
        """
        处理文件状态
            os.stat_result(st_mode=33261, st_ino=2990121, st_dev=64768, st_nlink=1, st_uid=0, st_gid=0, st_size=43408,
            st_atime=1616555896, st_mtime=1585714781, st_ctime=1614931154)

        :param cmd_stdout:
        :return:
        """
        _data = []

        partern = r'os.stat_result\(st_mode=(?P<st_mode>\d+), st_ino=(?P<st_ino>\d+), st_dev=(?P<st_dev>\d+), ' \
                  r'st_nlink=(?P<st_nlink>\d+), st_uid=(?P<st_uid>\d+), st_gid=(?P<st_gid>\d+), ' \
                  r'st_size=(?P<st_size>\d+), st_atime=(?P<st_atime>\d+), st_mtime=(?P<st_mtime>\d+), ' \
                  r'st_ctime=(?P<st_ctime>\d+)'

        _parser_data = re.match(partern, cmd_stdout, re.I).groupdict()
        _parser_data['st_atime'] = self.timestamp_to_string(int(_parser_data['st_atime']))
        _parser_data['st_mtime'] = self.timestamp_to_string(int(_parser_data['st_mtime']))
        _parser_data['st_ctime'] = self.timestamp_to_string(int(_parser_data['st_ctime']))

        return [_parser_data]

    @staticmethod
    def lsof(cmd_stdout, *args, **kwargs):
        """
            cmd must have -F param, for example:   lsof -p 4050 -F

           These are the fields that lsof will produce.  The single
           character listed first is the field identifier.

                a    file access mode
                c    process command name (all characters from proc or
                     user structure)
                C    file structure share count
                d    file's device character code
                D    file's major/minor device number (0x<hexadecimal>)
                f    file descriptor (always selected)
                F    file structure address (0x<hexadecimal>)
                G    file flaGs (0x<hexadecimal>; names if +fg follows)
                g    process group ID
                i    file's inode number
                K    tasK ID
                k    link count
                l    file's lock status
                L    process login name
                m    marker between repeated output
                M    the task comMand name
                n    file name, comment, Internet address
                N    node identifier (ox<hexadecimal>
                o    file's offset (decimal)
                p    process ID (always selected)
                P    protocol name
                r    raw device number (0x<hexadecimal>)
                R    parent process ID
                s    file's size (decimal)
                S    file's stream identification
                t    file's type
                T    TCP/TPI information, identified by prefixes (the
                     `=' is part of the prefix):
                         QR=<read queue size>
                         QS=<send queue size>
                         SO=<socket options and values> (not all dialects)
                         SS=<socket states> (not all dialects)
                         ST=<connection state>
                         TF=<TCP flags and values> (not all dialects)
                         WR=<window read size>  (not all dialects)
                         WW=<window write size>  (not all dialects)
                     (TCP/TPI information isn't reported for all supported
                       UNIX dialects. The -h or -? help output for the
                       -T option will show what TCP/TPI reporting can be
                       requested.)
                u    process user ID
                z    Solaris 10 and higher zone name
                Z    SELinux security context (inhibited when SELinux is disabled)
                0    use NUL field terminator character in place of NL
                1-9  dialect-specific field identifiers (The output
                     of -F? identifies the information to be found
                     in dialect-specific fields.)
        :param cmd_stdout:
        :return:
        """

        identifier = {
            'a': 'access',
            'c': 'command',
            'p': 'pid',
            'u': 'uid',
            'f': 'fd',
            't': 'type',
            's': 'size',
            'P': 'protocol',
            'T': 'TCP',
            'n': 'name',
            'L': 'user',
            'R': 'ppid',
            'g': 'gid',
            'S': 'stream'
        }

        opfile = []
        _f = dict()
        _p = dict()
        in_proc = False

        outline = cmd_stdout.split('\n')
        for of in outline:
            try:
                of = of.strip()

                if len(of) == 0:
                    continue
                elif len(of) == 1:
                    character = of
                    field = ""
                else:
                    character, field = of[0], of[1:]

                if character not in identifier.keys():
                    continue

                if character == 'p':
                    in_proc = True
                    _p = dict()
                    _p['pid'] = field
                    continue

                if character == 'f':
                    opfile.append(_f)
                    in_proc = False
                    _f = dict()
                    _f.update(_p)
                    _f['fd'] = field
                    continue

                if in_proc:
                    _p[identifier[character]] = field
                    continue

                else:
                    if character == 'T':
                        if field.startswith('ST'):
                            _f[identifier[character]] = field.split('=')[1]
                        else:
                            continue
                    else:
                        _f[identifier[character]] = field
                    continue
            except Exception as e:
                print(traceback.format_exc())
        else:
            opfile.append(_f)

        return opfile

    @staticmethod
    def process(cmd_stdout, *args, **kwargs):
        """
        获取进程信息

        UID        PID  PPID  C STIME TTY          TIME CMD
        root         1     0  0 04:27 ?        00:00:05 /usr/lib/systemd/systemd --switched-root --system --deserialize 21
        root         2     0  0 04:27 ?        00:00:00 [kthreadd]
        root       820     1  0 04:27 ?        00:00:00 /usr/sbin/gssproxy -D
        rpc        823     1  0 04:27 ?        00:00:00 /sbin/rpcbind -w
        dbus       829     1  0 04:27 ?        00:00:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
        libstor+   835     1  0 04:27 ?        00:00:00 /usr/bin/lsmd -d
        root       836     1  0 04:27 ?        00:00:00 /usr/sbin/smartd -n -q never

        :param cmd_stdout:
        :return:
        """
        fields = ['user', 'pid', 'ppid', 'c', 'stime', 'tty', 'time', 'cmd']

        def row_parse(values, row):

            # field num, except 'cmd' field.
            n = 7

            if len(values) == n:
                values.append(row)
                return

            val, o_val = row.split(' ', 1)
            if val:
                values.append(val)

            row_parse(values, o_val)

        # 排除空字符串
        if not cmd_stdout:
            return None
        proc = list()

        c = 0
        for content in cmd_stdout.split('\n'):

            if c == 0:
                c += 1
                continue

            if not content:
                continue

            values = list()
            row_parse(values, content)
            tmp = dict(zip(fields, values))

            proc.append(tmp)

        return proc

    @staticmethod
    def wlogin(cmd_stdout, *args, **kwargs):
        """
        w - Show who is logged on and what they are doing.

        [root@localhost collect]# w -i
        17:43:57 up 37 min,  3 users,  load average: 0.00, 0.03, 0.12
        USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
        root     :0       :0               17:15   ?xdm?   1:10   0.28s /usr/libexec/gnome-session-binary --session gnome-classic
        root     pts/0    :0               17:15    2:37   0.07s  0.07s bash
        root     pts/1    10.0.0.28        17:17    5.00s  0.27s  0.02s w -i

        :param cmd_stdout:
        :return:
        """

        # 排除空字符串
        if not cmd_stdout:
            return None
        login = list()

        c = 0
        for content in cmd_stdout.split('\n'):

            if c <= 1:
                c += 1
                continue

            if not content:
                continue

            tmp = dict()
            tmp['user'] = content[0:8].strip()
            tmp['tty'] = content[9:17].strip()
            tmp['from'] = content[18:34].strip()
            tmp['login_time'] = content[35:42].strip()
            tmp['idle'] = content[43:50].strip()
            tmp['jcpu'] = content[51:57].strip()
            tmp['pcpu'] = content[58:63].strip()
            tmp['what'] = content[64:].strip()
            login.append(tmp)

        return login

    @staticmethod
    def wtmp(cmd_stdout, *args, **kwargs):
        """
        [root@localhost ~]# who /var/log/wtmp
        root     :0           2021-03-09 10:39 (:0)
        root     pts/0        2021-03-09 10:41 (:0)
        root     pts/1        2021-03-09 10:47 (100.119.153.121)
        root     pts/2        2021-03-09 11:07 (100.119.153.121)
        root     :0           2021-03-10 17:15 (:0)
        root     pts/1        2021-03-10 17:17 (sf0001390586la)
        root     pts/0        2021-03-11 09:39 (:0)
        root     pts/1        2021-03-11 09:40 (100.119.153.121)
        root     pts/2        2021-03-11 17:14 (100.119.153.121)
        root     :0           2021-03-11 23:19 (:0)
        root     pts/0        2021-03-11 23:20 (:0)
        root     pts/1        2021-03-11 23:22 (sf0001390586la)
        root     pts/2        2021-03-12 00:04 (sf0001390586la)
        root     pts/4        2021-03-12 09:40 (100.119.153.121)

        :param output:
        :return:
        """

        # 排除空字符串
        if not cmd_stdout:
            return None
        wt = list()

        for content in cmd_stdout.split('\n'):

            if not content:
                continue

            tmp = dict()
            tmp['user'] = content[0:8].strip()
            tmp['line'] = content[9:21].strip()
            tmp['time'] = content[22:38].strip()
            tmp['comment'] = content[39:].strip()
            wt.append(tmp)

        return wt

    @staticmethod
    def shadow(cmd_stdout, *args, **kwargs):

        # 排除空字符串
        if not cmd_stdout:
            return None
        sh = list()

        for content in cmd_stdout.split('\n'):

            if not content:
                continue
            tmp = dict(
                zip(['username', 'password', 'last_change', 'min_change', 'max_change', 'warm',
                     'failed_expire', 'expiration', 'reserved'], content.split(':')))
            tmp['last_change'] = (date(1970, 1, 1) + timedelta(days=int(tmp['last_change']))).strftime('%Y-%m-%d')
            sh.append(tmp)

        return sh

    @staticmethod
    def password(cmd_stdout, *args, **kwargs):

        # 排除空字符串
        if not cmd_stdout:
            return None
        pa = list()

        for content in cmd_stdout.split('\n'):

            if not content:
                continue

            tmp = dict(
                zip(['username', 'password', 'uid', 'gid', 'allname', 'homedir', 'shell'], content.split(':'))
            )
            pa.append(tmp)

        return pa

    @staticmethod
    def netstat(cmd_stdout, *args, **kwargs):
        """

        [root@localhost net]# netstat -tlunpa 2>/dev/null
        Active Internet connections (servers and established)
        Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
        tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1086/sshd
        tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      1087/cupsd
        tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      1447/dnsmasq
        tcp        0      0 100.119.152.132:22      100.119.153.121:55766   ESTABLISHED 6218/sshd: root@pts
        tcp6       0      0 :::22                   :::*                    LISTEN      1086/sshd
        tcp6       0      0 :::111                  :::*                    LISTEN      685/rpcbind
        udp        0      0 0.0.0.0:111             0.0.0.0:*                           685/rpcbind
        udp6       0      0 ::1:323                 :::*                                696/chronyd
        udp6       0      0 :::856                  :::*                                685/rpcbind

        :return:
        """
        # 排除空字符串
        if not cmd_stdout:
            return None
        ne = list()

        c = 0
        for content in cmd_stdout.split('\n'):

            if not content:
                continue
            if c < 1:
                c += 1
                continue

            tmp = dict()
            tmp['proto'] = content[0:5].strip()
            tmp['recvq'] = content[6:12].strip()
            tmp['sendq'] = content[13:19].strip()
            tmp['local'] = content[20:43].strip()
            tmp['remote'] = content[44:67].strip()
            tmp['state'] = content[68:79].strip()
            try:
                tmp['pid'], tmp['program'] = content[80:].strip().split("/")
            except Exception as e:
                tmp['pid'] = '0'
                tmp['program'] = "-"

            ne.append(tmp)

        return ne

    @staticmethod
    def ipaddress(cmd_stdout, *args, **kwargs):
        """
        [root@localhost collect]# ip addr
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
            link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
            inet 127.0.0.1/8 scope host lo
               valid_lft forever preferred_lft forever
            inet6 ::1/128 scope host
               valid_lft forever preferred_lft forever
        2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
            link/ether 08:00:27:61:9e:bd brd ff:ff:ff:ff:ff:ff
            inet 100.119.152.132/22 brd 100.119.155.255 scope global noprefixroute dynamic enp0s3
               valid_lft 28158sec preferred_lft 28158sec
            inet6 fe80::50bc:382e:c298:3e2/64 scope link noprefixroute
               valid_lft forever preferred_lft forever
        3: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default qlen 1000
            link/ether 52:54:00:e0:e0:7f brd ff:ff:ff:ff:ff:ff
            inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
               valid_lft forever preferred_lft forever
        4: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast master virbr0 state DOWN group default qlen 1000
            link/ether 52:54:00:e0:e0:7f brd ff:ff:ff:ff:ff:ff

        :return:
        """
        # 排除空字符串
        if not cmd_stdout:
            return None
        ad = list()
        st = dict()
        for content in cmd_stdout.split('\n'):
            if not content:
                continue

            if re.match(r'^\d+.*', content, re.I):
                if st:
                    ad.append(st)
                st = dict()
                parser = re.match(r'^(?P<num>\d+):\s(?P<name>.*?):\s<(?P<dest>.*?)>\s(?P<options>.*)', content, re.I).groupdict()
                options = parser.pop('options').split(" ")
                a, b = list(), list()
                for r in range(len(options)):
                    if r % 2:
                        b.append(options[r])
                    else:
                        a.append(options[r])
                st.update(parser)
                st.update(dict(zip(a, b)))

            if re.match(r'\s+link/', content, re.I):
                st.update(re.match(r'^\s+link/(?P<type>.*?)\s(?P<mac>.*?)\s.*', content, re.I).groupdict())

            if re.match(r'^\s+inet.*', content, re.I):
                st.update(re.match(r'^\s+inet(?P<ipv>\d?)?\s(?P<addr>.*?)\s.*', content, re.I).groupdict())
        if st:
            ad.append(st)
        return ad

    @staticmethod
    def systemctl(cmd_stdout, *args, **kwargs):
        # 排除空字符串
        if not cmd_stdout:
            return None
        sy = list()

        c = 0
        for content in cmd_stdout.split('\n'):

            if not content:
                continue
            if c < 1:
                c += 1
                continue

            tmp = dict(zip(['unit', 'state'], [i for i in content.split(" ") if i]))
            sy.append(tmp)

        return sy

    @staticmethod
    def find(cmd_stdout, *args, **kwargs):
        # 排除空字符串
        if not cmd_stdout:
            return None
        fi = list()

        c = 0
        for content in cmd_stdout.split('\n'):

            if not content:
                continue
            if c < 1:
                c += 1
                continue
            fi.append(content)

        return fi

    @staticmethod
    def timestamp_to_string(timestamp):
        """
        将时间戳转化为字符串
        :param timestamp:
        :return:
        """
        time_struct = time.localtime(timestamp)
        return time.strftime('%Y-%m-%d %H:%M:%S', time_struct)

    def process_exe_filestats(self, cmd_stdout, *args, **kwargs):
        dataset = kwargs.pop('dataset')
        data = kwargs.pop('data')
        pid = data['from'].split('/')[2]
        print(pid)
        result = []
        for d in self.filestats(cmd_stdout, *args, **kwargs):
            d['pid'] = pid
            result.append(d)
        return result

    def command_stat(self, cmd_stdout, *args, **kwargs):

        result = list()
        f = dict()
        li01 = re.compile(r'^File:\s(?P<file>.*?)$')
        li02 = re.compile(r'^Size:\s(?P<size>\d+)\s+\tBlocks:\s(?P<blocks>\d+)\s+IO\sBlock:\s(?P<io_block>\d+)\s+(?P<file_type>.*?)$')
        li03 = re.compile(r'^Device:\s(?P<device>.*?)\tInode:\s(?P<inode>\d+)\s+Links:\s(?P<link>\d+)$')
        li04 = re.compile(r'^Access:\s\((?P<access>.*?)\)\s+Uid:\s\((?P<uid>.*?)\)\s+Gid:\s\((?P<gid>.*?)\)$')
        li05 = re.compile(r'^Context:\s(?P<context>.*?)$')
        li06 = re.compile(r'^Access:\s(?P<atime>.*?)$')
        li07 = re.compile(r'^Modify:\s(?P<mtime>.*?)$')
        li08 = re.compile(r'^Change:\s(?P<ctime>.*?)$')
        for line in cmd_stdout.split('\n'):
            line = line.strip()
            if line.startswith("File"):
                if f:
                    result.append(f)
                f = dict()
                line = line.replace('‘', '').replace('’', '')
            for pattern in [li01, li02, li03, li04, li05, li06, li07, li08]:
                match = pattern.match(line)
                if match:
                    f.update(match.groupdict())
        else:
            result.append(f)

        return result


if __name__ == '__main__':
    p = ParserCore()
    import os
    cmd = os.popen('ps -efwww')
    for item in p.process(cmd.read()):
        print(item)