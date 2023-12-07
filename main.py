# TODO: Check root permissions

import scans.scanner


def main():
    # Nmap command, will later be taken from config, profile or input
    results = scans.scanner.scan("127.0.0.1", "-T4 --top-ports 3")

    if results is None:
        print("An error as occurred")
        return

    print(results)


if __name__ == "__main__":
    main()
