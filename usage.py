#! /usr/bin/env python3.6

from os import path, listdir
import multiprocessing
from Tools.smtp import smtpscan
from Tools.discovery import Discovery
from Tools.dirb import Dirb
from Tools.smb import Smb
from Tools.ssh import ssh_scan
from Tools.snmp import snmp_scan
from Tools.ftp import ftp_scan
from Tools.dns import dns_scan
import re
from time import sleep
from notes import Settings,omnilog

options = ['SetOptions', 'Enumerate', 'LFI', 'webshell', 'jobs']





class Usage:
    def __init__(self, x):
        self.running_proc = 0
        self.max_processes = x
        self.jobs = []
        self.jobtype = []
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

    def checkproc(self):
        rp = 0
        i = 0
        while rp != len(self.jobs) and len(self.jobs) != 0:
            if self.jobs[i].is_alive() and self.jobs[i].exitcode is None:
                rp += 1
                i += 1
                continue
            elif self.jobs[i].is_alive() and self.jobs[i].exitcode is not None :
                self.jobs[i].terminate()
            else:
                self.jobs.pop(i)
                self.jobtype.pop(i)
                rp = 0
                i = 0
        self.running_proc = rp

    def multiproc(self, func, args, stype=None):
        if stype is None:
            stype = ''
        z = 0
        while 1:
            rp = 0
            i = 0
            while rp != len(self.jobs) and len(self.jobs) != 0:
                if self.jobs[i].is_alive() and self.jobs[i].exitcode is None:
                    rp += 1
                    i += 1
                    continue
                elif self.jobs[i].is_alive() and self.jobs[i].exitcode is not None:
                    self.jobs[i].terminate()
                else:
                    self.jobs.pop(i)
                    self.jobtype.pop(i)
                    rp = 0
                    i = 0

            if rp < self.max_processes:
                print("[INFO] {multiproc} Process now released", file=omnilog)
                break
            elif z == 60:
                print("[INFO] {multiproc} waiting for free process, %s in use" % str(rp), file=omnilog)
                z = 0
            z += 1
            sleep(1)
        p = multiprocessing.Process(target=func, args=args)
        p.daemon = True
        p.start()
        self.jobs.append(p)
        self.jobtype.append(stype)
        rp += 1
        self.running_proc = rp


class EnumOptions:
    list = [('callsmb', ['microsoft-ds', 'netbios-ssn'], [135, 139, 445]),
            ('callsmtp', ['smtp'], [25]),
            ('callssh', ['ssh'], [22]),
            ('callsnmp', ['snmp'], [161, 162]),
            ('callftp', ['ftp'], [21]),
            ('calldns', ['domain'], [53])]

    @staticmethod
    def discover(settings, usg):
        i = 0
        ck = 0
        if settings.allscan:
            print("[INFO] {discover} Discovery already complete", file=omnilog)
        else:
            for folder in listdir(settings.Workspace):
                match = re.match(r"([\d]{1,3}\.){3}[\d]{1,3}", folder)
                if match is not None:
                    n = settings.find_target(folder)
                    file = settings.Workspace + str(settings.targets[n].ip) \
                        + '/nmap/' + str(settings.targets[n].ip) + '-top-udp.xml'
                    if path.isfile(file) and not\
                            (settings.override and settings.targets[n].override):
                        Discovery.import_target(settings, n)
                    else:
                        ck += 1 # count of assets scanned
                        usg.multiproc(Discovery.scan_target, args=(settings, n), stype='nmap')
                        settings.targets[n].override = False

            if ck ==0:
                print("[INFO] {discover} Finished discovery", file=omnilog)
                settings.allscan = True
                
    @staticmethod            
    def importspace(scope: Settings):
        for folder in listdir(scope.Workspace):
            match = re.match(r"([\d]{1,3}\.){3}[\d]{1,3}", folder)
            if match is not None:
                n = scope.find_target(folder)
                file = scope.Workspace + str(scope.targets[n].ip) \
                       + '/nmap/' + str(scope.targets[n].ip) + '-top-udp.xml'
                if path.isfile(file):
                    Discovery.import_target(scope, n)

    @staticmethod
    def checkservices(settings, n, usg):
        m = 0
        for x in settings.targets[n].services:
            if x.enum:
                continue
            elif x.web and x.enum is False:
                usg.multiproc(Dirb.all_web, (settings, n))
                settings.targets[n].setwebenum()

            else:
                for y in range(0, len(EnumOptions.list)):
                    if (int(x.port) in EnumOptions.list[y][2] or x.name in EnumOptions.list[y][1])\
                            and x.enum is False:
                        settings.targets[n].services[m].enum = True
                        func = getattr(EnumOptions, EnumOptions.list[y][0])
                        usg.multiproc(func, (settings, n, m), stype=EnumOptions.list[y][0])
            m += 1

    @staticmethod
    def callsmb(settings, n, m):
        Smb.scan(settings, n=n)

    @staticmethod
    def callsmtp(settings, n, m):
        smtpscan(settings, n, m)

    @staticmethod
    def callssh(settings, n, m):
        ssh_scan(settings, n, m)

    @staticmethod
    def callsnmp(settings, n, m):
        snmp_scan(settings, n, m)

    @staticmethod
    def callftp(settings, n, m):
        ftp_scan(settings, n, m)

    @staticmethod
    def calldns(settings, n, m):
        dns_scan(settings, n, m)

# class LFI():
#     notes = 'LFI'
#
#     class downloader():
#         system_files = 'useful_system_files.txt'
#
#     class Lpoison():
#         log_pwn = 'log_poisoning_options.txt'
#         code = 'php'  # code type of website
#         code_options = [['[0] asp', '[1] py', '[2] php (default)'],
#                         ['asp', 'py', 'php']]  # Possible option for web script language
#
#
# class webshell():
#     cmd = 'cmd'  # command varialble in url


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





