from . import port_scanner_facade

def scan(target, arg, args=None, timeout=None):
    if "-vv" not in arg:
        arg = "-vv " + arg

    scanner = port_scanner_facade.PortScannerFacade()
    scanResults = scanner.scanCommand(target, arg, args, timeout)

    return scanResults
