#! /usr/bin/env python3.6

import subprocess
from notes import omnilog

def dns_scan(settings, n, m):
    print("[INFO] [host: %s] {dns_scan} starting enumeration" % settings.targets[n].ip)
    print("[INFO] [host: %s] {dns_scan} starting enumeration" % settings.targets[n].ip, file=omnilog)
    tar_ip = settings.targets[n].ip
    port = settings.targets[n].services[m].port
    #out_dir = settings.tool_dir(n, 'dirb')  # Change tool dir name
    #outfile = out_dir + "outformat"     # Change

    notes = '~' * 20
    notes += '\n dns_scan scan results'
    notes += '\n' + '~' * 20
    command = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (
        tar_ip)  # grab the hostname
    try:
        host = subprocess.check_output(command, shell=True).strip()
        host = host.decode('ascii')
        print(host)
        print("[INFO] [host: %s] {dns_scan} Attempting Domain Transfer on %s" %(settings.targets[n].ip,host), file=omnilog)
        ZT = "dig @ thinc.local axfr" % tar_ip
        ztresults = subprocess.check_output(ZT, shell=True).decode('ascii')
        if "failed" in ztresults:
            print("INFO: Zone Transfer failed for " + host, file=omnilog)
        else:
            notes += "[*] Zone Transfer successful for " + host + "(" + tar_ip + ")!!! [see output file]"
            notes += ztresults
    except:
        print("[ERROR] [host: %s] {dns_scan} Enumeration Failed" % settings.targets[n].ip, file=omnilog)

    settings.tool_notes(n, '', notes, 'dns-summary.txt')   # Change summary filename
    print("[INFO] [host: %s] {dns_scan} Completed enumeration" % settings.targets[n].ip, file=omnilog)
    print("[INFO] [host: %s] {dns_scan} Completed enumeration" % settings.targets[n].ip)