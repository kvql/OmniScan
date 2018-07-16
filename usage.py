#! /usr/bin/env python3.6

from os import path, listdir
import multiprocessing
from Tools.smtp import smtpscan
from Tools.discovery import Discovery
from Tools.dirb import Dirb
from Tools.smb import Smb
import re

options = ['SetOptions', 'Enumerate', 'LFI', 'webshell', 'jobs']





class Usage:
    def __init__(self, x):
        self.running_proc = 0
        self.max_processes = x
        self.jobs = []
    @staticmethod
    def cli():
        command = input("\nworkflow > ")
        return command

    @staticmethod
    def SetOptions(self):
        command = ''
        while (command != 'quit'):
            i = 1
            for txt in options:
                print("[%d] %s" % (i, txt))
                i += 1
            command = Usage.cli()

    @staticmethod
    def printoptions(obj):
        i = 1
        for txt in obj.__dict__:
            if txt[0] != '_':
                print("[%d] %s: %s" % (i, txt, getattr(obj, txt)))
                i += 1

    def multiproc(self, func, args):
        rp = 0
        for i in range(len(self.jobs)):
            if self.jobs[i].is_alive():
                rp += 1
                continue
            else:
                self.jobs.pop(i)
                break
        if self.running_proc >= self.max_processes:
            while 1:
                for i in range(len(self.jobs)):
                    if self.jobs[i].is_alive():
                        rp += 1
                        continue
                    else:
                        self.jobs.pop(i)
                        break
        else:
            p = multiprocessing.Process(target=func, args=args)
            p.daemon = True
            p.start()
            self.jobs.append(p)
            rp += 1
            print("running proc: %s" % str(rp))
            self.running_proc = rp


class EnumOptions:
    list = [('dirb','http'),
            ('callsmb', 'microsoft-ds', 135, 139, 445),
            ('callsmtp', 'smtp',25)]
    @staticmethod
    def discover(settings, usg):
        i = 0
        for folder in listdir(settings.Workspace):
            match = re.match(r"([\d]{1,3}\.){3}[\d]{1,3}",folder)
            if match is not None:
                n = settings.find_target(folder)
                file = settings.Workspace + str(settings.targets[n].ip) \
                    + '/nmap/' + str(settings.targets[n].ip) +'-top-udp.xml'
                if path.isfile(file):
                    settings.targets[n].scan = True
                    usg.multiproc(Discovery.import_target, args=(settings, n))
                else:
                    usg.multiproc(Discovery.scan_target, args=(settings, n))
                    settings.targets[n].scan = True

    @staticmethod
    def checkservices(settings, n, usg):
        m = 0
        for x in settings.targets[n].services:
            if x.enum:
                m = m
            elif x.web:
                usg.multiproc(Dirb.all_web, (settings, n))

            else:
                for y in range(0, len(EnumOptions.list)):
                    if x.port in EnumOptions.list[y] or x.name in EnumOptions.list[y]:
                        func = getattr(EnumOptions, EnumOptions.list[y][0])
                        usg.multiproc(func, (settings, n, m))
            m += 1

    @staticmethod
    def callsmb(settings, n, m):
        Smb.scan(settings, n=n)
        settings.targets[n].services[m].enum = True

    @staticmethod
    def callsmtp(settings, n, m):
        smtpscan(settings, n, m)
        settings.targets[n].services[m].enum = True



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





