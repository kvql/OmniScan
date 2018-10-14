
import xml.etree.ElementTree as ET
import subprocess
from notes import omnilog
from os import path,devnull


class Smb:
    #
    # @staticmethod
    # def integrateNmap(settings, filePath):
    #     if os.path.isfile(filePath) == False:
    #          print('[ERROR] No Results found for: %s' % filePath)
    #     f = open(filePath, 'r')
    #     # Warning
    #     # The xml.etree.ElementTree module is not secure against maliciously constructed data.
    #     # If you need to parse untrusted or unauthenticated data see XML vulnerabilities.
    #     # script will be privesc risk if nmap net mask set to global write
    #     tree = ET.parse(filePath)
    #     root = tree.getroot()
    #     i = 0
    #     h = 0
    #
    #     for host in root.iter('host'):  # loop through host found in nmap file
    #         print(host.tag, host.attrib)
    #         mac = ''
    #         n = 0
    #         for address in host.iter('address'):  # loop through addresses for this host, mac and ip
    #             if address.attrib['addrtype'] == "mac":
    #                 mac = address.attrib['addr']
    #             elif address.attrib['addrtype'] == "ipv4":
    #                 ip = address.attrib['addr']
    #                 n = settings.find_target(ip)  # get index of current target ip or create new target
    #             else:
    #                 print('[ERROR] unknown address type: %s' % address.attrib['addrtype'])
    #                 return
    #         settings.targets[n].mac = mac
    #         for child in host.iter('script'):
    #             print(child.tag)
    #             for a in child.attrib:
    #                 print(a, '\t'+child.attrib[a])
    #                 #print(a.value)

    @staticmethod
    def scan(settings, ip=None, n=None):
        if ip is None and n is None:
            print('[ERROR] Need to specify ip or index', file=omnilog)
            return
        elif ip is not None:
            n = settings.find_target(ip)

        n = int(n)
        tar_ip = settings.targets[n].ip
        print("[INFO]{smb.scan} SMB scan starting for host: %s" % tar_ip)
        print("[INFO]{smb.scan} SMB scan starting for host: %s" % tar_ip, file=omnilog)
        out_dir = settings.tool_dir(n,'smb')

        notes = '~' * 20
        notes += '\n smb_scan scan results'
        notes += '\n' + '~' * 20
        null = open(devnull, 'w')
        # Enumeration scan
        try:

            print("[INFO]{smb.scan} starting enum4linux for host: %s" % tar_ip, file=omnilog)
            smbscan = settings.proxypass + "enum4linux -a %s" % tar_ip
            notes += '\n' + smbscan
            results = subprocess.check_output(smbscan, shell=True, stderr=null)
            notes += '\nSee folder for enum4linux results'
            settings.tool_notes(n, 'smb', results, 'enum-results.txt')
        except:
            print("[ERROR] [host: %s] {snmp_scan} enum4linux Enumeration Failed" % settings.targets[n].ip, file=omnilog)


        try:
            print("[INFO] [host: %s] {snmp_scan} nmap Enumeration starting" % settings.targets[n].ip, file=omnilog)
            nmap_vuln = settings.proxypass+"nmap -v -Pn -p 135,139,445 --script=smb-vuln* -oX '%s/nmap-vulns' %s" \
                        % (out_dir, tar_ip)
            notes += '\n' + '~' * 20
            notes += '\n nmap smb results'
            notes += '\n' + '~' * 20
            notes += '\n' + nmap_vuln + '\n'
            results = subprocess.check_output(nmap_vuln, shell=True)
            notes += results.decode('ascii')
        except:
            print("[ERROR] [host: %s] {snmp_scan} nmap Enumeration Failed" % settings.targets[n].ip, file=omnilog)
        settings.tool_notes(n, '', notes, 'smb-summary.txt')
        print("[INFO]{smb.scan} SMB scan complete for host: %s" % tar_ip, file=omnilog)
        print("[INFO]{smb.scan} SMB scan complete for host: %s" % tar_ip)


if __name__ == "__main__":
    from notes import *
    f = open('/opt/Scripts/targets.txt', 'r')
    scope = Settings(r'/opt/test/testing/')

    for ip in f:
        tmp = ip.replace("\n", "")
        scope.targets.append(Target(tmp))

    Smb.scan(scope, ip='10.11.1.145')
    #smb.integrateNmap(scope, '/opt/test/smb-vuln')