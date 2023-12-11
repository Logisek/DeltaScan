# TODO: Check root permissions

import scans.scanner
import db.data_handler


def main():
    # Nmap command, will later be taken from config, profile or input
    host = "127.0.0.1"
    arguments = "-sV -T4 --top-ports 3"

    results = scans.scanner.scan(host, arguments)

    if results is None:
        print("An error as occurred")
        return

    save = db.data_handler.DataHandler()
    save.saveScan(results, arguments)
    print("Done! :)")


if __name__ == "__main__":
    main()
