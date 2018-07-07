#! /usr/bin/env python3.6
import usage
import notes


if __name__ == "__main__":

    scope=usage.Settings
    command=''
    while(command!='quit'):
        usage.printoptions(scope)
        command = usage.cli()

        #if command.isdigit():
            #run =





