# TODO: Proper error handling
# TODO: Validate host/hosts input
# TODO: Further sanitize input

import nmap
import shlex


def performScan(rawCommand):
    nmapArgs = shlex.split(rawCommand)

    # Extract host
    nmapHost = nmapArgs.pop(-1)

    # Draft sanitization of raw command
    if nmapArgs[0] == "nmap":
        nmapArgs.pop(0)

    try:
        # Check port argument
        if not any(arg.startswith("-p") for arg in nmapArgs):
            raise ValueError("No ports argument parsed.")

        # Convert list to str for argument parsing
        nmapArgs = " ".join(nmapArgs)

        nm = nmap.PortScanner()

        scanResults = nm.scan(nmapHost, arguments=nmapArgs)
        scanResults = nm.csv()

    except Exception as e:
        logf = open("error.log", "a")
        logf.write("nmap died: " + str(e) + "\n")
        print("New error log entry.")
        scanResults = "An error has occurred."

    return scanResults
