# TODO: Check root permissions

import scans.port_scanner

def main():

    scanResults = scans.port_scanner.performScan()
    print(scanResults)

if __name__ == "__main__":
    main()
