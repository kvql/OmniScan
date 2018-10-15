#! /usr/bin/env python3.6

import subprocess
from notes import omnilog

def ftp_scan(settings, n, m):
    print("[INFO] [host: %s] {ftp_scan} starting enumeration" % settings.targets[n].ip)
    print("[INFO] [host: %s] {ftp_scan} starting enumeration" % settings.targets[n].ip, file=omnilog)
    tar_ip = settings.targets[n].ip
    port = settings.targets[n].services[m].port
    out_dir = settings.tool_dir(n, 'ftp')
    outfile = out_dir + "nmap-ftp"
    errfile = out_dir + 'error.log'

    notes = '~' * 20
    notes += '\n ftp_scan scan results'
    notes += '\n' + '~' * 20

    # try:
    print("[INFO] [host: %s] {ftp_scan} starting nmap ftp enumeration" % settings.targets[n].ip, file=omnilog)
    ftpnmap = settings.proxypass + "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce," \
              "ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221" \
              " -oN %s %s" % (
                  port, outfile, tar_ip)
    notes += '\n Command: ' + ftpnmap
    results = subprocess.check_output(ftpnmap, shell=True)
    notes += results.decode('ascii')
    notes += '\n\n' + '~' * 20
    notes += '\n Hydra Results'
    notes += '\n' + '~' * 20
    # except:
    #     print("[ERROR] [host: %s] {ftp_scan} nmap Enumeration Failed" % settings.targets[n].ip)

    try:
        outfile = out_dir + "hydra-ftp"
        print("[INFO] [host: %s] {ftp_scan} starting ftp hydra" % settings.targets[n].ip, file=omnilog)
        for x in open('/opt/dev/workflow/wordlists/ftp-seclist.txt', 'r'):
            tmp = x.split(':')
            # HYDRA = settings.proxypass + "hydra -t 4 -I -L /opt/wordlists/userlist -P " \
            #         "/opt/wordlists/offsecpass " \
            #         "-f -o %s -u %s -s %s ftp" % (
            # outfile, tar_ip, port)
            HYDRA = settings.proxypass + "hydra -t 4 -I -l %s -p %s -f -o %s -u %s -s %s ftp" %\
                    (tmp[1], tmp[2], outfile, tar_ip, port)
            results = subprocess.check_output(HYDRA, shell=True, stderr=errfile).decode('ascii')
            resultarr = results.split("\n")
            for result in resultarr:
                if "login:" in result:
                    notes += "\n[*] Valid ftp credentials found: " + result
    except:
        print("[ERROR] [host: %s] {ftp_scan} HYDRA Enumeration Failed" % settings.targets[n].ip, file=omnilog)

    settings.tool_notes(n, '', notes, 'ftp-summary.txt')
    print("[INFO] [host: %s] {ftp_scan} Completed enumeration" % settings.targets[n].ip, file=omnilog)
    print("[INFO] [host: %s] {ftp_scan} Completed enumeration" % settings.targets[n].ip)
