#! /usr/bin/env python3.6
from os import path, makedirs


class Settings:
    def __init__(self, Workspace):
        self.Workspace = Workspace
        self.OS_options = [['linux', 'windows'], [r'/opt/workflow/linux/', r'/opt/workflow/windows/']]
        self.targets = []
        self.proxypass = ''
        self.ck_workspace()

    def toggle_tunnel(self):
        if self.proxypass == '':
            self.proxypass = 'proxychains '
        else:
            self.proxypass = ''

    def tool_notes(self,n,folder,s,name):
        dir = self.tool_dir(n,folder)
        f = open(dir+name, 'w')
        print('[INFO] file opened')
        for st in str(s).split('\\n'):
            print(st, file=f)
        f.close()

    def tool_dir(self, n, folder):
        dir = self.Workspace + str(self.targets[n].ip)+'/'+folder+'/'  # folder name must include '/'
        if path.isdir(dir):
            print('[INFO] [host: %s] {tool_dir} Tools Dir, %s, exists' % (self.targets[n].ip, folder))
        else:
            makedirs(dir)  # creates dir path if doesn't exist

            if path.isdir(dir):
                print('[INFO] [INFO] [host: %s] {tool_dir} Tools Dir, %s, created' % (self.targets[n].ip, folder))
            else:
                print('[INFO] [INFO] [host: %s] {tool_dir} Tools Dir, %s, could not be created'
                      % (self.targets[n].ip, folder))  # returns false if dir could not be created
                return False
        return dir

    def ck_workspace(self):
        dir = self.Workspace
            #returns false if dir could not be created

    def find_target(self, ip):
        i = 0
        for asset in self.targets:
            if asset.ip == ip:
                return i
            else:
                i += 1
        self.targets.append(Target(ip))
        ip_dir = self.Workspace + str(self.targets[i].ip) + '/'
        if path.isdir(ip_dir):
            print("[INFO] [host: %s] {find_target} Target directory exist" % ip)
        else:
            makedirs(ip_dir)       # creates dir path if doesn't exist

            if path.isdir(ip_dir):
                print("[INFO] [host: %s] {find_target} Target directory created" % ip)
            else:
                print("[ERROR] [host: %s] {find_target} Target directory could not be created" % ip)
        return i


class Target:

    class os():
        linux = r'/opt/workflow/linux/'

    def __init__(self, ip):
        self.ip = ip
        self.scan = False   #set true once nmap scan run

    mac = ''
    name = ''
    OS = os.linux
    OS_name = ''
    OS_acc = 0
    services = []

    def find_port(self, m):
        i = 0
        for x in self.services:
            if x.port == str(m):
                return i
            else:
                i +=1
        print('[ERROR] Port number,%s, not found' % m)
        return 0

    def add_service(self, srv):           #shortened function to append new service
        i = 0
        for x in self.services:
            if x.protocol == srv.protocol and x.port == srv.port:
                self.services[i]=srv
                print("[INFO] {add_service} service %s was updated" % x.port)
                return
            i += 1
        self.services.append(srv)
        print("[INFO] {add_service} service %s was added" % srv.port)


class Service:
    def __init__(self, prot, port, name=None, product=None,extra=None):
        self.protocol = prot
        self.port = port  # service port number
        self.name = name
        self.product = product  # include version
        self.extra = extra
        self.enum = False  # Set to true when enumeration running,
        # leave true when complete, set false if it fails
        self.addweb()

    def addweb(self):
        self.web = Parsing.web(self.name)
        if not self.web:
            return
        self.https = Parsing.https(self.name)
        self.pages = []
        self.dirs = []

    def web_proto(self):
        if self.https:
            return 'https://'
        else:
            return 'http://'

class Parsing:

    http_dict = {'http', 'www', 'www-http'}
    https_dict = {'https', 'ssl/https'}

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