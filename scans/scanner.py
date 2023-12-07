from . import port_scanner_facade

def scan(target, arg, args=None, timeout=None):
    scanner = port_scanner_facade.PortScannerFacade()
    scanResults = scanner.scanCommand(target, arg, args, timeout)

    return scanResults
