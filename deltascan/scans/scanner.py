from . import port_scanner_facade


def scan(target, arg, args=None, timeout=None):
    """
    Perform a scan on the specified target using the given arguments.

    Args:
        target (str): The target to scan.
        arg (str): The arguments to pass to the scanner.
        args (str, optional): Additional arguments to pass to the scanner. Defaults to None.
        timeout (int, optional): The timeout for the scan in seconds. Defaults to None.

    Returns:
        dict: The scan results.
    """
    if "-vv" not in arg:
        arg = "-vv " + arg

    scanner = port_scanner_facade.PortScannerFacade()
    scanResults = scanner.scanCommand(target, arg, args, timeout)

    return scanResults
