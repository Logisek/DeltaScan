import scans.scanner
import db.data_handler
import presentation.data_presentation
import inquirer
import logging
import os
import re

logging.basicConfig(level=logging.INFO)


def main():
    # checkRootPermissions()
    action = getAction()
    handleAction(action)


def view():
    # Scan list
    scanList = db.data_handler.DataHandler().getScanList()
    presentation.data_presentation.displayScanList(scanList)

    # Profile list
    profileList = db.data_handler.DataHandler().getProfileList()
    presentation.data_presentation.displayProfileList(profileList)

    # Results
    results = db.data_handler.DataHandler().getScanResults(1)
    presentation.data_presentation.displayScanResults(results)

    print("Viewed scan list.")


def checkRootPermissions():
    if os.getuid() != 0:
        logging.error("You need root permissions to run this program.")
        print("You need root permissions to run this program.")
        exit()


def getAction():
    options = [
        inquirer.List(
            "action",
            message="What do you want to do?",
            choices=["Scan", "View", "Exit"],
        )
    ]

    return inquirer.prompt(options)


def handleAction(action):
    if action is not None:
        if action["action"] == "Scan":
            scan()
        elif action["action"] == "View":
            view()
        elif action["action"] == "Exit":
            exit()


def validate_host(answers, current):
    if not re.match(r"^[a-zA-Z0-9.-/]+$", current):
        return "Invalid host. Please enter a valid IP address, domain name, or network address."
    return True


def validate_arguments(answers, current):
    if not re.match(r"^[a-zA-Z0-9\s-]+$", current):
        return "Invalid arguments. Please enter only alphanumeric characters, spaces, and hyphens."
    return True


def scan():
    # Validate user input
    options = [
        inquirer.Text(
            "host", message="Enter target host or network", validate=validate_host
        ),
        inquirer.Text(
            "arguments", message="Nmap arguments", validate=validate_arguments
        ),
    ]

    answers = inquirer.prompt(options)

    results = None
    arguments = None

    if answers is not None:
        host = answers["host"]
        arguments = answers["arguments"]

        results = scans.scanner.scan(host, arguments)

    if results is None:
        logging.error("An error occurred during the scan. Please check your host and arguments.")
        return

    save = db.data_handler.DataHandler()
    save.saveScan(results, arguments)
    print("Done! :)")


if __name__ == "__main__":
    main()
