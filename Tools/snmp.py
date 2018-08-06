#! /usr/bin/env python3.6

import subprocess


def snmp_scan(settings, n, m):
    print("[INFO] [host: %s] {snmp_scan} starting enumeration" % settings.targets[n].ip)
    tar_ip = settings.targets[n].ip
    port = settings.targets[n].services[m].port
    out_dir = settings.tool_dir(n, 'snmp')

    notes = '~' * 20
    notes += '\n snmp_scan scan results'
    notes += '\n' + '~' * 20
    command = settings.proxypass + " onesixtyone %s" % tar_ip
    try:
        print("[INFO] [host: %s] {snmp_scan} starting onesixtyone scan" % settings.targets[n].ip)
        notes += '\n' + command
        results = subprocess.check_output(command, shell=True).strip()
        notes += results.decode('ascii')
        if results != "":
            if "Windows" in results:
                results = results.split("Software: ")[1]
                snmpdetect = 1
            elif "Linux" in results:
                results = results.split("[public] ")[1]
                snmpdetect = 1
            else:
                snmpdetect = 0

            if snmpdetect == 1:
                notes += "[*] SNMP running on " + tar_ip + "; OS Detect: " + results
                outfile = out_dir + "snmp-walk.txt"
                command = settings.proxypass + " snmpwalk -c public -v1 %s 1 > " \
                                               "%s" % (tar_ip, outfile)
                print("[INFO] [host: %s] {snmp_scan} starting SNMPWalk scan" % settings.targets[n].ip)
                notes += '\n' + '~' * 20
                notes += '\n' + command
                notes += subprocess.check_output(command, shell=True).decode('ascii')
    except:
        print("[ERROR] [host: %s] {snmp_scan} onesixtyone Enumeration Failed" % settings.targets[n].ip)
    try:
        outfile = out_dir + "snmp-nmap"
        command = settings.proxypass + \
            " nmap -sV -sU -Pn -p 161,162 --script=snmp* %s -oA %s" \
            % (tar_ip, outfile)
        print("[INFO] [host: %s] {snmp_scan} starting nmap snmp scripts scan" % settings.targets[n].ip)
        notes += '\n' + '~' * 20
        notes += '\n' + command
        results = subprocess.check_output(command, shell=True)
        notes += '\n' + results.decode('ascii')
    except:
        print("[ERROR] [host: %s] {snmp_scan} Nmap Enumeration Failed" % settings.targets[n].ip)

    # notes += '\n' + '~' * 20
    # notes += '\n' + 'Tools not properly Parsed, Check tool outputs!'
    # notes += '\n' + '~' * 20
    settings.tool_notes(n, '', notes, 'snmp-summary.txt')
    print("[INFO] [host: %s] {snmp_scan} Enumeration complete" % settings.targets[n].ip)