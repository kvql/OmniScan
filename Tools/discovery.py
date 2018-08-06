#! /usr/bin/env python3.6

from multiprocessing import Process
import subprocess
import xml.etree.ElementTree as ET
from os import path,devnull
from notes import *



class Discovery:
    @staticmethod
    def host_summary(settings, n):
        print("[INFO] [host: %s] {host summary} Staring summary print" % settings.targets[n].ip)
        notes = '~'*20
        notes += '\nSummary of host: %s' % settings.targets[n].ip
        notes += '\n' + '~' * 20
        notes += '\nIP:\t%s' % settings.targets[n].ip
        notes += '\nHostname:\t%s' % settings.targets[n].name
        notes += '\nOS:\t%s\t%s' % (settings.targets[n].os_f, settings.targets[n].os_name)

        notes += '\n' + '~' * 20+ '\n'
        if len(settings.targets[n].services) >0:
            y = 0
            for txt in settings.targets[n].services[0].__dict__:
                if txt[0] != '_' and not callable(getattr(settings.targets[n].services[0], txt)):
                    notes += "%s\t" % txt
                if txt == 'extra':      # Stops printing after extra
                    break
                y += 1
            for s in settings.targets[n].services:
                notes += '\n'
                z = 0
                for p in s.__dict__:
                    if txt[0] != '_':
                        notes += "%s\t" % getattr(s, p)
                    if z ==y:           # Stops printing after extra
                        break
                    z += 1
            notes += '\n' + '~' * 20 + '\n'
        settings.tool_notes(n, '', notes, 'summary.txt')
        print("[INFO] [host: %s] {host summary} Finished summary print" % settings.targets[n].ip)

    @staticmethod
    def integrateNmap(settings, filePath):
        if path.isfile(filePath) is False:
            print('[ERROR] No Results found for: %s' % filePath)
        #f = open(filePath, 'r')
        # Warning
        # The xml.etree.ElementTree module is not secure against maliciously constructed data.
        # If you need to parse untrusted or unauthenticated data see XML vulnerabilities.
        # script will be privesc risk if nmap net mask set to global write
        try:
            tree = ET.parse(filePath)
        except:
            print("[ERROR] {integrateNmap} failed to parse %s" % filePath)
            return
        root = tree.getroot()
        i = 0
        h = 0

        for host in root.iter('host'):      # loop through host found in nmap file
            #print(host.tag, host.attrib)
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
                    if child.tag == 'osmatch' and int(child.attrib['accuracy']) >= settings.targets[n].os_acc:
                        settings.targets[n].os_name = child.attrib['name']
                        settings.targets[n].os_acc = int(child.attrib['accuracy'])
                    elif child.tag == 'osclass' and int(child.attrib['accuracy']) >= settings.targets[n].os_acc:
                        settings.targets[n].os_f = child.attrib['osfamily']
                        settings.targets[n].os_acc = int(child.attrib['accuracy'])
                    elif (child.tag == 'osmatch' or child.tag == 'osclass') and \
                            int(child.attrib['accuracy']) < settings.targets[n].os_acc:
                        break
            y = 0
            for xport in host.iter('port'):             # Iterate through port trees in file
                state = xport.find('state')
                ps = state.attrib['state']

                if ps == 'open':
                    try:
                        xservice = xport.find('service')    # Find service tree within port tree
                        proto = xport.attrib['protocol']
                        p = xport.attrib['portid']
                        try:
                            nm = xservice.attrib['name']         # Parse service name
                        except:
                            nm = ''
                        try:
                            prd = xservice.attrib['product']
                            try:
                                prd += xservice.attrib['version']
                            except:
                                print("[warning] [host %s] {integaratenmap} No version found for port: %s" %
                                      (settings.targets[n].ip, p))
                        except:
                            print("[warning] [host %s] {integaratenmap} No Product found for port: %s" %
                                  (settings.targets[n].ip, p))
                            prd = ''

                        try:
                            ext = xservice.attrib['extrainfo']
                        except:
                            ext = ''
                        new_service = Service(
                            prot=proto, port=p, name=nm, product=prd, extra=ext)
                        settings.targets[n].add_service(new_service)
                        print("[INFO] [host %s] {integaratenmap} Added service %s" %
                              (settings.targets[n].ip, settings.targets[n].services[y].port))
                        y += 1
                    except:
                        print("[ERROR] {integaratenmap} host %s: Failed to add service " %
                              settings.targets[n].ip)
        print('[INFO] [host %s]Finished Import of nmap results for: %s' % (settings.targets[n].ip,filePath))
        # End of function

    @staticmethod
    def scan_target(settings, n):
        n = int(n)
        tar_ip = settings.targets[n].ip
        null = open(devnull, 'w')

        out_dir = settings.tool_dir(n,'nmap')
        if out_dir is False:
            print('[ERROR] Are you running as root?')
            return False
        print("[INFO] [host: %s] {scan_target} Starting top port TCP scan" %
              settings.targets[n].ip)
        nmap_top=settings.proxypass+"nmap -v -Pn -sV -sC -sS -T 3 --top-ports=100 " \
                                    "--host-timeout 1800 -O -oA '%s%s-top-ports' %s" % (
                                     out_dir, tar_ip, tar_ip)
        subprocess.check_output(nmap_top, shell=True, stderr=null)
        # print("[INFO] {scan_target} Starting integration of '%s%s-top-ports.xml" % (out_dir, tar_ip))
        # Discovery.integrateNmap(settings,'%s%s-top-ports.xml' % (out_dir, tar_ip))

        print("[INFO] [host: %s] {scan_target} Starting full TCP scan" %
              settings.targets[n].ip)
        nmap_tcp = settings.proxypass+"nmap -v -Pn -sV -sC -sS -T 4 --host-timeout 1800 -p- -O -oA " \
                                      "'%s%s-all-tcp' %s" %(out_dir, tar_ip, tar_ip)
        subprocess.check_output(nmap_tcp, shell=True, stderr=null)
        # print("[INFO] {scan_target} Starting integration of '%s%s-all-tcp.xml" % (out_dir, tar_ip))
        # Discovery.integrateNmap(settings, '%s%s-all-tcp.xml' % (out_dir, tar_ip))

        print("[INFO] [host: %s] {scan_target} Starting UDP scan" %
              settings.targets[n].ip)
        nmap_udp = settings.proxypass + "nmap -v -Pn -sV -sC -sU -T 4 --max-retries 3 --host-timeout 1800 " \
                                        "--top-ports 200  -oA '%s%s-top-udp' %s" % (
                                         out_dir, tar_ip, tar_ip)
        subprocess.check_output(nmap_udp, shell=True, stderr=null)
        #print("[INFO] {scan_target} Starting integration of '%s%s-top-udp.xml" % (out_dir, tar_ip))
        #Discovery.integrateNmap(settings, '%s%s-top-udp.xml' % (out_dir, tar_ip))

        #Discovery.host_summary(settings, n)

        return True

    @staticmethod
    def import_target(settings, n):
        tar_ip = settings.targets[n].ip

        out_dir = settings.tool_dir(n, 'nmap')
        if out_dir is False:
            print('[ERROR] Are you running as root?')
            return False
        print("[INFO] {scan_target} Starting integration of '%s%s-top-ports.xml" % (out_dir, tar_ip))
        Discovery.integrateNmap(settings, '%s%s-top-ports.xml' % (out_dir, tar_ip))

        print("[INFO] {scan_target} Starting integration of '%s%s-all-tcp.xml" % (out_dir, tar_ip))
        Discovery.integrateNmap(settings, '%s%s-all-tcp.xml' % (out_dir, tar_ip))

        print("[INFO] {scan_target} Starting integration of '%s%s-top-udp.xml" % (out_dir, tar_ip))
        Discovery.integrateNmap(settings, '%s%s-top-udp.xml' % (out_dir, tar_ip))

        Discovery.host_summary(settings, n)

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
    from notes import Settings
    from usage import Target
    f = open('/opt/Scripts/targets.txt', 'r')
    scope = Settings(r'/opt/test/testing/')

    for ip in f:
        tmp = ip.replace("\n", "")
        scope.targets.append(Target(tmp))

    for target in scope.targets:
        jobs = []
        p = Process(target=Discovery.scan_target, args=(scope,target.ip,))
        jobs.append(p)
        p.start()

    f.close()