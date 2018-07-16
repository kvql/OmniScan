#! /usr/bin/env python3.6
from notes import Settings
from usage import *


if __name__ == "__main__":

    scope = Settings('/opt/pwk/public/')
    usg = Usage(3)
    command=''
    # tar = '/tmp/msf-db-rhosts-20180715-2103-fg7jgb'
    # f = open(tar, 'r')
    #
    # for ip in f:
    #     tmp = ip.replace("\n", "")
    #     scope.find_target(tmp)

    EnumOptions.discover(scope, usg)
    EnumOptions.checkservices(scope, 0, usg)
    while command != 'quit':
        #print(pool)
        #Usage.printoptions(scope)
        command = Usage.cli()

        #if command.isdigit():
            #run =





