# TODO: Proper error handling

import nmap
# import logging

def performScan():
    try:
        scanner = nmap.PortScanner()
        scanResults = scanner.scan('127.0.0.1', '22-443')
        print(scanner.command_line())

    except Exception as e:
        logf = open('error.log', 'a')
        logf.write('nmap died: ' + str(e) + '\n')
        print('New error log entry.')
        scanResults = 'An error has occured.'

    return scanResults