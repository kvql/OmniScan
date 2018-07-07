#!/usr/bin/env python3.6

import sys
import subprocess
import os
#import notes
import xml.etree.ElementTree as ET
from usage import *
from notes import Settings

class smb:

    @staticmethod
    def integrateNmap(settings, filePath):
        if os.path.isfile(filePath) == False:
             print('[ERROR] No Results found for: %s' % filePath)
        f = open(filePath, 'r')
        # Warning
        # The xml.etree.ElementTree module is not secure against maliciously constructed data.
        # If you need to parse untrusted or unauthenticated data see XML vulnerabilities.
        # script will be privesc risk if nmap net mask set to global write
        tree = ET.parse(filePath)
        root = tree.getroot()
        i = 0
        h = 0

        for host in root.iter('host'):  # loop through host found in nmap file
            print(host.tag, host.attrib)
            mac = ''
            n = 0
            for address in host.iter('address'):  # loop through addresses for this host, mac and ip
                if address.attrib['addrtype'] == "mac":
                    mac = address.attrib['addr']
                elif address.attrib['addrtype'] == "ipv4":
                    ip = address.attrib['addr']
                    n = settings.find_target(ip)  # get index of current target ip or create new target
                else:
                    print('[ERROR] unknown address type: %s' % address.attrib['addrtype'])
                    return
            settings.targets[n].mac = mac
            for child in host.iter('script'):
                print(child.tag)
                for a in child.attrib:
                    print(a, '\t'+child.attrib[a])
                    #print(a.value)

    @staticmethod
    def scan(settings, ip, n=None):
        if ip is None and n is None:
            print('[ERROR] Need to specify ip or index')
            return
        elif ip is not None:
            n = settings.find_target(ip)

        tar_ip = settings.targets[n].ip

        out_dir = settings.tool_dir(n,'smb/')

        # Enumeration scan
        smbscan = "enum4linux -a %s" % (ip)
        results = subprocess.check_output(smbscan, shell=True)

        settings.tool_notes(n, 'smb', results, 'enum-results.txt')

        # Nmap nse scripts
        # nmap -v -p 445 --script=smb-vuln* 10.11.1.145 -oX smb-vuln
        nmap_vuln = settings.proxypass+"nmap -v -Pn -p 135,445 --script=smb-vuln* -oX '%s%s-nmap-vulns' %s" % (
        out_dir, tar_ip, tar_ip)

        subprocess.call(nmap_vuln, shell=True)

        # if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        #     print "[*] SAMRDUMP User accounts/domains found on " + ip
        #     lines = nbtresults.split("\n")
        #     for line in lines:
        #         if ("Found" in line) or (" . " in line):
        #             print "   [+] " + line
        #print(results)


if __name__ == "__main__":

    f = open('/opt/Scripts/targets.txt', 'r')
    scope = Settings(r'/opt/test/testing/')

    for ip in f:
        tmp = ip.replace("\n", "")
        scope.targets.append(Target(tmp))

    smb.scan(scope,ip='10.11.1.145')
    #smb.integrateNmap(scope, '/opt/test/smb-vuln')