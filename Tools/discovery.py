#! /usr/bin/env python3.6

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import xml.etree.ElementTree as ET
from usage import *
from notes import Settings


import time

class discovery:
    @staticmethod
    def host_summary(settings, n):
        notes = '~'*20
        notes += '\nSummary of host: %s' % settings.targets[n].ip
        notes += '\n' + '~' * 20
        notes += '\nIP:\t%s' % settings.targets[n].ip
        notes += '\nHostname:\t%s' % settings.targets[n].name
        notes += '\nOS:\t%s\t%s' % (settings.targets[n].OS,settings.targets[n].OS_name)

        notes += '\n' + '~' * 20+ '\n'
        for txt in Target.Service.__dict__:
            if txt[0] != '_':
                notes += "%s\t" % txt
        for s in settings.targets[n].services:
            notes += '\n'
            for p in s.__dict__:
                if txt[0] != '_':
                    notes += "%s\t" % getattr(s, p)
        notes += '\n' + '~' * 20 + '\n'
        settings.tool_notes(n, '', notes, 'summary.txt')






    @staticmethod
    def multProc(targetin, scanip, port):
        jobs = []
        p = multiprocessing.Process(target=targetin, args=(scanip,port))
        jobs.append(p)
        p.start()
        return

    class options:
        targets=[]
        flags=''



    @staticmethod
    def integrateNmap(settings, filePath):
        if os.path.isfile(filePath) == False:
            print('[ERROR] No Results found for: %s' % filePath)
        f = open(filePath, 'r')
        #Warning
        #The xml.etree.ElementTree module is not secure against maliciously constructed data.
        # If you need to parse untrusted or unauthenticated data see XML vulnerabilities.
        # script will be privesc risk if nmap net mask set to global write
        tree = ET.parse(filePath)
        root = tree.getroot()
        i = 0
        h = 0

        for host in root.iter('host'):      # loop through host found in nmap file
            print(host.tag, host.attrib)
            mac = ''
            n = 0
            for address in host.iter('address'):    # loop through addresses for this host, mac and ip
                if address.attrib['addrtype'] == "mac":
                    mac = address.attrib['addr']
                elif address.attrib['addrtype'] == "ipv4":
                    ip = address.attrib['addr']
                    n = settings.find_target(ip)   # get index of current target ip or create new target
                else:
                    print('[ERROR] unknown address type: %s' % address.attrib['addrtype'])
                    return
            settings.targets[n].mac = mac

            for OS in host.iter('os'):
                for child in OS.iter():
                    if child.tag == 'osmatch' and int(child.attrib['accuracy']) >= settings.targets[n].OS_acc:
                        settings.targets[n].OS_name = child.attrib['name']
                        settings.targets[n].OS_acc = int(child.attrib['accuracy'])
                    elif child.tag == 'osclass' and int(child.attrib['accuracy']) >= settings.targets[n].OS_acc:
                        settings.targets[n].OS = child.attrib['osfamily']
                        settings.targets[n].OS_acc = int(child.attrib['accuracy'])

            for port in host.iter('port'):
                state = port.find('state')
                ps = state.attrib['state']
                if ps == 'open':
                    pt = port #.find('port')
                    srv = port.find('service')
                    proto = pt.attrib['protocol']
                    p = pt.attrib['portid']
                    nm = srv.attrib['name']
                    prd = srv.attrib['product'] +srv.attrib['version']
                    try:
                        ext = srv.attrib['extrainfo']
                    except:
                        ext=''
                    settings.targets[n].sv(Target.Service(
                        prot=proto, port=p, name=nm, product=prd, extra=ext))
        print('[INFO] Finished Import of nmap results for: '+filePath)
        #End of function

    @staticmethod
    def scan_target(settings, ip, n=None):
        if ip is None and n is None:
            print('[ERROR] Need to specify ip or index')
            return
        elif ip is not None:
            n = settings.find_target(ip)

        tar_ip = settings.targets[n].ip

        out_dir = settings.tool_dir(n,'nmap/')
        if out_dir is False:
            print('[ERROR] Are you running as root?')
            return False

        nmap_top=settings.proxypass+"nmap -v -Pn -sV -sC -sS -T 6 --top-ports=100 -O -oA '%s%s-top-ports' %s" % (
            out_dir, tar_ip, tar_ip)
        subprocess.call(nmap_top, shell=True)
            #import results
        print('a')

            #run enumeration
        nmap_tcp = settings.proxypass+"nmap -v -Pn -sV -sC -sS -T 4 -p- -O -oA '%s%s-all-tcp' %s" %(
            out_dir, tar_ip, tar_ip)
        subprocess.call(nmap_tcp, shell=True)
        print('b')
        nmap_udp = settings.proxypass + "nmap -v -Pn -sV -sC -sS -T 4 -p- -O -oA '%s%s-top-udp' %s" % (
            out_dir, tar_ip, tar_ip)
        subprocess.call(nmap_tcp, shell=True)

        return True


if __name__ == "__main__":
    # create target folder in workspace
    # create nmap folder
    # summary.txt
    # [dir] Top-100-oA
    # [dir] All-ports-oA
    # Full scan of top 100 ports
    # if "0 hosts up" returned, either add further flags or create warning
    # nmap -sC -sV -A --top-ports=100 ip
    f = open('/opt/Scripts/targets.txt', 'r')
    scope = Settings(r'/opt/test/testing/')

    for ip in f:
        tmp = ip.replace("\n", "")
        scope.targets.append(Target(tmp))

    integrateNmap(scope, scope.Workspace+scope.targets[0].ip+'/'+'nmap/'+scope.targets[0].ip+'-top-ports.xml')
      # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
    # for target in scope.targets:
    #     jobs = []
    #     p = multiprocessing.Process(target=scan_target, args=(scope,target.ip,))
    #     jobs.append(p)
    #     p.start()
    # f.close()