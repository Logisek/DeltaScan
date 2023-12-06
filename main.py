# TODO: Check root permissions

import scans.port_scanner


def main():
    # Nmap raw command; will be later taken from config, profile or input
    nmapCommand = "nmap -Pn -T4 -p 22-443 127.0.0.1"

    scanResults = scans.port_scanner.performScan(nmapCommand)

    print(scanResults)


if __name__ == "__main__":
    main()
