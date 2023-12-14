import scans.scanner
import db.data_handler
import presentation.data_presentation
import reports.pdf_generator
import inquirer
import logging
import os
import re

logging.basicConfig(level=logging.INFO)


class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing results, and generating reports.
    """

    def __init__(self):
        self.dataHandler = db.data_handler.DataHandler()

    def main(self):
        """
        Entry point of the program.
        """
        # self.checkRootPermissions()
        action = self.getAction()
        self.handleAction(action)

    def view(self):
        """
        Displays the scan list, profile list, and scan results.
        """
        scanList = self.dataHandler.getScanList()
        presentation.data_presentation.displayScanList(scanList)

        profileList = self.dataHandler.getProfileList()
        presentation.data_presentation.displayProfileList(profileList)

        results = self.dataHandler.getScanResults(1)
        presentation.data_presentation.displayScanResults(results)

        print("Viewed scan list.")

    def pdfReport(self):
        """
        Generates a PDF report based on the scan results.
        """
        results = self.dataHandler.getScanResults(1)
        reports.pdf_generator.generatePdfReport("default", results)

    def checkRootPermissions(self):
        """
        Checks if the program is running with root permissions.
        """
        if os.getuid() != 0:
            logging.error("You need root permissions to run this program.")
            print("You need root permissions to run this program.")
            exit()

    def getAction(self):
        """
        Prompts the user to select an action.
        """
        options = [
            inquirer.List(
                "action",
                message="What do you want to do?",
                choices=["Scan", "View", "Report", "Exit"],
            )
        ]

        return inquirer.prompt(options)

    def handleAction(self, action):
        """
        Handles the selected action.
        """
        if action is not None:
            if action["action"] == "Scan":
                self.scan()
            elif action["action"] == "View":
                self.view()
            elif action["action"] == "Report":
                self.pdfReport()
            elif action["action"] == "Exit":
                exit()

    def validate_host(self, answers, current):
        """
        Validates the entered host.
        """
        if not re.match(r"^[a-zA-Z0-9.-/]+$", current):
            return "Invalid host. Please enter a valid IP address, domain name, or network address."
        return True

    def validate_arguments(self, answers, current):
        """
        Validates the entered arguments.
        """
        if not re.match(r"^[a-zA-Z0-9\s-]+$", current):
            return "Invalid arguments. Please enter only alphanumeric characters, spaces, and hyphens."
        return True

    def scan(self):
        """
        Performs a scan based on the entered host and arguments.
        """
        options = [
            inquirer.Text(
                "host",
                message="Enter target host or network",
                validate=self.validate_host,
            ),
            inquirer.Text(
                "arguments",
                message="Nmap arguments",
                validate=self.validate_arguments,
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
            logging.error(
                "An error occurred during the scan. Please check your host and arguments."
            )
            return

        save = self.dataHandler
        save.saveScan(results, arguments)
        print("Done! :)")


if __name__ == "__main__":
    app = DeltaScan()
    app.main()
