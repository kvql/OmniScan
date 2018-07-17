#! /usr/bin/env python3.6

import subprocess


def func(settings, n, m):               # Change
    print("[INFO] [host: %s] {func} starting enumeration" % settings.targets[n].ip)
    tar_ip = settings.targets[n].ip
    port = settings.targets[n].services[m].port
    out_dir = settings.tool_dir(n, 'dirb')  # Change tool dir name
    outfile = out_dir + "outformat"     # Change

    notes = '~' * 20
    notes += '\n func scan results'     # Change
    notes += '\n' + '~' * 20
    command = settings.proxypass + " hydra " \
            "%s -u %s -s %s ssh" % (outfile, tar_ip, port)
    try:
        print("[INFO] [host: %s] {func} starting enumeration" % settings.targets[n].ip)
        results = subprocess.check_output(command, shell=True)
        resultarr = results.split("\n")
        # ### add tool function here
    except:
        print("[ERROR] [host: %s] {func} Enumeration Failed" % settings.targets[n].ip)

    print("[INFO] [host: %s] {func} starting enumeration" % settings.targets[n].ip)
    settings.tool_notes(n, '', notes, 'smtp-summary.txt')   # Change summary filename