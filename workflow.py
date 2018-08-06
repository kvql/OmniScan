#! /usr/bin/env python3.6
from notes import Settings, printoptions
from usage import *


if __name__ == "__main__":

    scope = Settings('/opt/pwk/public/')
    command=''
    usg = Usage(8)
    # tar = '/tmp/msf-db-rhosts-20180715-2103-fg7jgb'
    # f = open(tar, 'r')
    #
    # for ip in f:
    #     tmp = ip.replace("\n", "")
    #     scope.find_target(tmp)
    scope.override = False
    # while command != 'quit':
    #     EnumOptions.discover(scope, usg)
    #     sleep(10)
    #     for i in range(0, len(scope.targets)):
    #         EnumOptions.checkservices(scope, i, usg)
    #     command = Usage.cli()
    EnumOptions.importspace(scope)

    options = ['show options', 'Set Global Options', 'Set override','Scan IP', 'Scan List', 'Jobs']
    while command !='q':

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

        elif command == 'Scan IP':
            ntar = scope.listtar()
            if ntar is not None:
                EnumOptions.checkservices(scope, ntar, usg)

        elif command == 'Jobs':
            usg.checkproc()
            print("running processes: %d" % usg.running_proc)

        else:                                   # read command from user
            print("Unknown command, See options:")
            j = 0
            for x in options:
                print("[%d] %s" % (j, x))
                j += 1
        command = input("omnisploit> ")
        if command.isdigit():               # if digit find command
            i = int(command)
            if i < len(options):
                command = options[i]
