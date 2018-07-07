#! /usr/bin/env python3.6

options = ['SetOptions', 'Enumerate', 'LFI', 'webshell', 'jobs']


def cli():
    command = input("\nworkflow > ")
    return command

def SetOptions(self):
    command = ''
    while (command != 'quit'):
        i = 1
        for txt in options:
            print("[%d] %s" % (i, txt))
            i += 1
        command = cli()





def printoptions(object):
    i = 1
    for txt in object.__dict__:
        if txt[0] != '_':
            print("[%d] %s: %s" % (i, txt, getattr(object, txt)))
            i += 1


# class os():
#     class linux():
#         resources = r'/opt/workflow/linux/'


class LFI():
    notes = 'LFI'

    class downloader():
        system_files = 'useful_system_files.txt'

    class Lpoison():
        log_pwn = 'log_poisoning_options.txt'
        code = 'php'  # code type of website
        code_options = [['[0] asp', '[1] py', '[2] php (default)'],
                        ['asp', 'py', 'php']]  # Possible option for web script language


class webshell():
    cmd = 'cmd'  # command varialble in url


class Parsing:

    http_dict = {'http', 'www', 'www-http'}
    https_dict = {'https','ssl/https',}

    @staticmethod
    def http(var):
        txt = str(var)
        for txt in Parsing.http_dict:
            if txt == var:
                return True
        return False

    @staticmethod
    def https(var):
        txt = str(var)
        for txt in Parsing.https_dict:
            if txt == var:
                return True
        return False

    @staticmethod
    def web(var):
        txt = str(var)
        if Parsing.http(txt) or Parsing.https(txt):
            return True
        else:
            return False


class Target:

    class os():
        linux = r'/opt/workflow/linux/'

    def __init__(self, ip):
        self.ip = ip

    mac = ''
    name = ''
    OS = os.linux
    OS_name = ''
    OS_acc = 0
    services = []

    def find_port(self, m):
        i = 0
        for x in self.services:
            if x.port == m:
                return i
            else:
                i +=1

    def sv(self,srv):           #shortened function to append new service
        i=0
        for x in self.services:
            if x.protocol == srv.protocol and x.port == srv.port:
                self.services[i]=srv
            else:
                self.services.append(srv)
            i+=1

    class Service:
        def __init__(self, prot, port, name=None, product=None,extra=None):
            self.protocol = prot
            self.port = port  # service port number
            self.name = name
            self.product = product  # include version
            self.web = Parsing.web(self.name)
            self.extra = extra
            self.enum = False  # Set to true when enumeration running,
            # leave true when complete, set false if it fails

            if self.web:
                self.addweb()

        def addweb(self):
            self.web == True
            self.https = Parsing.web(self.name)
            self.pages = []
            self.dirs = []

        def web_proto(self):
            if self.https:
                return 'https://'
            else:
                return 'http://'
