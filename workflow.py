#! /usr/bin/env python3.6
from notes import Settings
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
    while command != 'quit':
        EnumOptions.discover(scope, usg)
        sleep(10)
        for i in range(0, len(scope.targets)):
            EnumOptions.checkservices(scope, i, usg)
        command = Usage.cli()






