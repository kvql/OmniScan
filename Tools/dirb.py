#!/usr/bin/env python3.6

import sys
import os
import subprocess
from notes import Settings
from Tools.discovery import *


class Dirb:

    @staticmethod
    def all_web(settings, n):
        if settings.targets.length >= n:
            print('[ERROR] index out of bounds')
            return
        for x in settings.targets[n].services:
            if x.web:
                Dirb.scan(settings,x.port,n)

    @staticmethod
    def summary(n, settings, dirs, pages):
        notes = '~'*20
        notes += '\n DIRECTORIES FOUND'
        notes += '\n' + '~'*20
        for x in dirs:
            notes += '\n'+x

        notes = '\n'+'~' * 20
        notes += '\n Pages FOUND'
        notes += '\n'+'~' * 20
        for x in pages:
            notes += '\n'+x

        settings.tool_notes(n, 'dirb', notes, 'dirb-summary.txt')

    @staticmethod
    def scan(settings, m, n=None, ip=None):
        if ip is None and n is None:                            # Function to check targets ip
            print('[ERROR] Need to specify ip or index')
            return
        elif ip is not None:
            n = int(settings.find_target(ip))                        # find target or create new
        else:
            n = 0
        tar_ip = settings.targets[n].ip                         # Set target ip
        out_dir = settings.tool_dir(n, 'dirb')
        proto = settings.targets[n].services[m].web_proto()
        port = settings.targets[n].services[m].port
        url = proto+tar_ip+ ':' + port + '/'        # Build url of target

        folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]  # Folders with word lists

        found = []          # list to store pages
        found_dir = []      # list to store directories
        print("INFO: Starting dirb scan for " + url)
        for folder in folders:
            for filename in os.listdir(folder):

                outfile = " -o " + out_dir + proto +'--'+ port + "_dirb_" + filename
                dirbscan = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
                try:
                    results = subprocess.check_output(dirbscan, shell=True)
                    resultarr = results.split("\n")
                    for line in resultarr:
                        if "+" in line:
                            if line not in found:
                                found.append(line)
                        elif "==>" in line:
                            if line not in found_dir:
                                found_dir.append(line)
                except:
                    pass

        try:
            if found[0] != "" and found_dir[0] != "":
                print("[*] Dirb found the following items...")
                for item in found:
                    print("   " + item)
        except:
            print("INFO: No items found during dirb scan of " + url)
        settings.targets[n].services[m].pages = found
        settings.targets[n].services[m].dirs = found_dir
        Dirb.summary(n,settings, found_dir, found)



if __name__ == "__main__":
    f = open('/opt/Scripts/targets.txt', 'r')
    scope = Settings(r'/opt/test/testing/')
    for ip in f:
        tmp = ip.replace("\n", "")
        scope.targets.append(Target(tmp))

    integrateNmap(scope, scope.Workspace+scope.targets[0].ip+'/'+'nmap/'+scope.targets[0].ip+'-top-ports.xml')
    port_index = scope.targets[0].find_port(10000)
    Dirb.scan(scope, port_index, n=0)
