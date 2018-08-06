#! /usr/bin/env python3.6
from os import path, makedirs
import re

def printoptions(obj):
    i = 1
    for txt in obj.__dict__:
        if txt[0] != '_' and txt != ('shellcode' or 'responses'):
            print("[%d] %s: %s" % (i, txt, getattr(obj, txt)))
            i += 1

class Settings:
    def __init__(self, Workspace):
        self.Workspace = Workspace
        self.OS_options = [['linux', 'windows'], [r'/opt/workflow/linux/', r'/opt/workflow/windows/']]
        self.targets = []
        self.proxypass = ''
        self.ck_workspace()
        self.allscan = False
        self.override = False

    def toggle_tunnel(self):
        if self.proxypass == '':
            self.proxypass = 'proxychains '
        else:
            self.proxypass = ''

    def tool_notes(self,n,folder,s,name):
        dir = self.tool_dir(n,folder)
        f = open(dir+name, 'w')
        print('[INFO] {tool_notes} file opened: %s' % dir+name)
        for st in str(s).split('\\n'):
            print(st, file=f)
        f.close()
        print("[INFO] {tool_notes} Print complete")

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

    def listtar(self):
        i = 0
        for ip in self.targets:
            print('[%d] %s' % (i, self.targets[i].ip))
            i += 1
        print('[-1] add new target')
        x = input("Enter number of your target > ")
        if x == '-1':
            newip = input("Enter number of your target > ")
            match = re.match(r"([\d]{1,3}\.){3}[\d]{1,3}", newip)
            if match is not None:
                n = self.find_target(newip)
                return n
            else:
                print("wrong format")
        elif x.isdigit():
            if int(x) < len(self.targets):
                return int(x)
        else:
            print("Wrong input")

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

    def setoptions(self):
        print("Enter ':q' to quit, or hit Enter key to keep value:")
        for name in self.__dict__:
            if name[0] != '_' and name != 'shellcode':
                x = input("Enter new value for %s, Current value: %s\n%s\t> " % (name,
                                                                                 str(self.__getattribute__(name)),
                                                                                 name))
                if x == ':q':
                    break
                if x != '' and type(self.__getattribute__(name)) == str:
                    self.__setattr__(name, x)
                elif x != '' and type(self.__getattribute__(name)) == int:
                    if x.isdigit():
                        self.__setattr__(name, int(x))
                    elif x != '':
                        print("[ERROR] incorrect value")
                elif x != '' and type(self.__getattribute__(name)) == bytes:
                    if len(x) == 1:
                        self.__setattr__(name, bytes(x, 'ascii'))
                    elif x != '':
                        print("[ERROR] incorrect value")
                elif x != '' and type(self.__getattribute__(name)) == bool:
                    if self.__getattribute__(name):
                        self.__setattr__(name, False)
                    elif not self.__getattribute__(name):
                        self.__setattr__(name, True)


class Target:
    def __init__(self, ip):
        self.ip = ip
        self.scan = False   #set true once nmap scan run
        self.mac = ''
        self.name = ''
        self.os_f = ''
        self.os_name = ''
        self.os_acc = 0
        self.services = []
        self.override = True

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

    def setwebenum(self):
        i = 0
        for x in self.services:
            if x.web:
                self.services[i].enum = True


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