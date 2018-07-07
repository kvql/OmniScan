#! /usr/bin/env python3.6

import sys
import usage
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
            print(st, f)
        f.close()

    def tool_dir(self, n, folder):
        dir = self.Workspace+self.targets[n].ip+'/'+folder+'/'  # folder name must include '/'
        if path.isdir(dir):
            print('[INFO] Workspace exist')
        else:
            makedirs(dir)  # creates dir path if doesn't exist

            if path.isdir(dir):
                print('[INFO] Created Workspace')
            else:
                print('[INFO] Could Not create workspace Dir')  # returns false if dir could not be created
                return False
        return dir

    def ck_workspace(self):
        dir = self.Workspace
        if path.isdir(dir):
            return 'Workspace exist'
        else:
            makedirs(dir)       # creates dir path if doesn't exist

            if path.isdir(dir):
                return 'Created Workspace'
            else:
                return 'Could Not create workspace Dir'    #returns false if dir could not be created

    def find_target(self, ip):
        i = 0
        for asset in self.targets:
            if asset.ip == ip:
                return i
            else:
                i += 1
        self.targets.append(usage.Target(ip))
        return i

