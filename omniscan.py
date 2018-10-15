#! /usr/bin/env python3.6
from notes import Settings, printoptions
from usage import *
import traceback
import argparse

banner = '\
 ▒█████   ███▄ ▄███▓ ███▄    █  ██░   █████    ███▄     ▄▄       ███▄    █\n\
▒██▒  ██▒▓██▒▀█▀ ██▒ ██ ▀█   █ ░██░▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █\n\
▒██░  ██▒▓██    ▓██░▓██  ▀█ ██▒▒██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒\n\
▒██   ██░▒██    ▒██ ▓██▒  ▐▌██▒░██░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒\n\
░ ████▓▒░▒██▒   ░██▒▒██░   ▓██░░██░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░\n\
░ ▒░▒░▒░ ░ ▒░   ░  ░░ ▒░   ▒ ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ \n\
  ░ ▒ ▒░ ░  ░      ░░ ░░   ░ ▒░ ▒ ░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░\n\
░ ░ ░ ▒  ░      ░      ░   ░ ░  ▒ ░░  ░  ░  ░          ░   ▒      ░   ░ ░ \n\
    ░ ░         ░            ░  ░        ░  ░ ░            ░  ░         ░ \n\
                                            ░'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # parser.add_argument('-t', type=str, required=True, help="The 1.15")
    parser.add_argument('-T', dest="targets", help="Input payload file path")
    # parser.add_argument('-p', type=bool, help="set this flag to use proxy", default=False)
    parser.add_argument('-N', default=False, action='store_true')
    parser.add_argument('--path', dest="filename", help="project home directory", required=True)

    args = parser.parse_args()
    print(banner)

    if args.filename[-1] != '/':
        path = args.filename + '/'
    else:
        path = args.filename

    scope = Settings(path)  # include / at the end of path
    command=''
    usg = Usage(8)  # setting the max number of concurrent processes
    if args.targets is not None:
        tar = args.targets      # = '/opt/pwk/exam/targets'
        f = open(tar, 'r')

        for ip in f:
            tmp = ip.replace("\n", "")
            scope.find_target(tmp)
    scope.override = args.N
    # while command != 'quit':
    #     EnumOptions.discover(scope, usg)
    #     sleep(10)
    #     for i in range(0, len(scope.targets)):
    #         EnumOptions.checkservices(scope, i, usg)
    #     command = Usage.cli()
    EnumOptions.importspace(scope)

    options = ['show options', 'Set Global Options', 'Set override', 'Full Scan of IP', 'Full Scan of All',
               'Enumerate IP', 'Scan List', 'Jobs','Summary']
    while command !='q':

        try:
            if command == 'show options':
                print("~~~~~~~~~~~ Print of global Options  ~~~~~~~~~~~")
                printoptions(scope)
            elif command == 'Set Global Options':
                scope.setoptions()

            elif command == 'Set override':
                if scope.override:
                    scope.override = False
                    print("override set to False")
                else:
                    scope.override = True
                    print("override set to True")

            elif command == 'Full Scan of IP':
                ntar = scope.listtar()
                if ntar != -1 and type(ntar) == int:
                    usg.multiproc(Discovery.scan_target, args=(scope, ntar), stype='nmap')
                    scope.targets[ntar].override = False
                    sleep(20)
                    while 'nmap' in usg.jobtype:
                        sleep(120)
                        Discovery.import_target(scope, ntar)
                        EnumOptions.checkservices(scope, ntar, usg)
                        usg.checkproc()
                        print("running processes: %d" % usg.running_proc)
                        print(usg.jobtype)

            elif command == 'Full Scan of All':
                # need to add code to set overide on every target
                EnumOptions.discover(scope, usg)
                while 'nmap' in usg.jobtype:
                    EnumOptions.discover(scope, usg)
                    sleep(20)
                    for i in range(0, len(scope.targets)):
                        EnumOptions.checkservices(scope, i, usg)
                    usg.checkproc()
                    print("running processes: %d" % usg.running_proc)

            elif command == 'Enumerate IP':
                ntar = scope.listtar()
                if ntar != -1 and type(ntar) == int:
                    EnumOptions.checkservices(scope, ntar, usg)

            elif command == 'Jobs':
                usg.checkproc()
                print("running processes: %d" % usg.running_proc)
                print(usg.jobtype)
            elif command == 'Summary':
                summary = "summary of scanned targets"
                summary += '\n' + '~' * 20
                for x in scope.targets:
                    summary += 'IP: ' + x.ip
                    tcp = 'TCP: '
                    udp = 'UDP: '
                    for s in x.services:
                        if s.protocol == 'tcp':
                            tcp += s.port + ','
                        elif s.protocol == 'udp':
                            udp += s.port + ','
                    summary += '\n' + tcp + '\n' + udp + '\n'

                    summary += '\n'+'~'*20
                print(summary)

            else:                                   # read command from user
                print("Unknown command, See options:")
                j = 0
                for x in options:
                    print("[%d] %s" % (j, x))
                    j += 1
        except Exception:
            print(traceback.format_exc())

        command = input("omnisploit> ")
        if command.isdigit():               # if digit find command
            i = int(command)
            if i < len(options):
                command = options[i]
