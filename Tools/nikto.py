#! /usr/bin/env python3.6

import subprocess
from notes import omnilog

def nikto_scan(settings, n, m):
    print("[INFO] [host: %s] {nikto_scan} starting enumeration" % settings.targets[n].ip)
    print("[INFO] [host: %s] {nikto_scan} starting enumeration" % settings.targets[n].ip, file=omnilog)
    tar_ip = settings.targets[n].ip
    port = settings.targets[n].services[m].port
    #out_dir = settings.tool_dir(n, 'dirb')  # Change tool dir name
    #outfile = out_dir + "outformat"     # Change

    notes = '~' * 20
    notes += '\n Nikto_scan scan results'
    notes += '\n' + '~' * 20
    command = "nikto -host %s -p %s" % (tar_ip, port)
    try:
        host = subprocess.check_output(command, shell=True).strip()
        results = host.decode('ascii')
        notes += '\n'+results

    except:
        print("[ERROR] [host: %s] {nikto_scan} Enumeration Failed" % settings.targets[n].ip, file=omnilog)

    settings.tool_notes(n, '', notes, 'nikto-'+str(port)+'-summary.txt')   # Change summary filename
    print("[INFO] [host: %s] {nikto_scan} Completed enumeration" % settings.targets[n].ip, file=omnilog)
    print("[INFO] [host: %s] {nikto_scan} Completed enumeration" % settings.targets[n].ip)