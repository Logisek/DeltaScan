import deltascan.scans.scanner as scanner
import deltascan.db.data_handler as data_handler
import deltascan.presentation.data_presentation as data_presentation
import deltascan.reports.pdf_generator as pdf_generator
import inquirer
import logging
import os
import re

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing results, and generating reports.
    """

    def __init__(self):
        self.dataHandler = data_handler.DataHandler()

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
        try:
            scanList = self.dataHandler.getScanList()
            data_presentation.displayScanList(scanList)

            profileList = self.dataHandler.getProfileList()
            data_presentation.displayProfileList(profileList)

            results = self.dataHandler.getScanResults(1)
            data_presentation.displayScanResults(results)

        except Exception as e:
            logging.error(f"{str(e)}")

    def pdfReport(self):
        """
        Generates a PDF report based on the scan results.
        """
        try:
            results = self.dataHandler.getScanResults(1)
            pdf_generator.generatePdfReport("default", results)
        except Exception as e:
            logging.error(f"{str(e)}")

    def checkRootPermissions(self):
        """
        Checks if the program is running with root permissions.
        """
        try:
            if os.getuid() != 0:
                raise PermissionError("You need root permissions to run this program.")
        except PermissionError as e:
            logging.error(e)
            print("You need root permissions to run this program.")
            exit()
        except Exception as e:
            logging.error(f"{str(e)}")

    def getAction(self):
        """
        Prompts the user to select an action.
        """
        try:
            options = [
                inquirer.List(
                    "action",
                    message="What do you want to do?",
                    choices=["Scan", "View", "Report", "Exit"],
                )
            ]

            return inquirer.prompt(options)
        except Exception as e:
            logging.error(f"{str(e)}")

    def handleAction(self, action):
        """
        Handles the selected action.
        """
        try:
            if action is not None:
                if action["action"] == "Scan":
                    self.scan()
                elif action["action"] == "View":
                    self.view()
                elif action["action"] == "Report":
                    self.pdfReport()
                elif action["action"] == "Exit":
                    exit()
        except Exception as e:
            logging.error(f"{str(e)}")

    def validate_host(self, answers, current):
        """
        Validates the entered host.
        """
        try:
            if not re.match(r"^[a-zA-Z0-9.-/]+$", current):
                return "Invalid host. Please enter a valid IP address, domain name, or network address."
            return True
        except Exception as e:
            logging.error(f"{str(e)}")

    def validate_arguments(self, answers, current):
        """
        Validates the entered arguments.
        """
        try:
            if not re.match(r"^[a-zA-Z0-9\s-]+$", current):
                return "Invalid arguments. Please enter only alphanumeric characters, spaces, and hyphens."
            return True
        except Exception as e:
            logging.error(f"{str(e)}")

    def scan(self):
        """
        Performs a scan based on the entered host and arguments.
        """
        try:
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
                raise ValueError("Wrong host or arguments.")

            save = self.dataHandler
            save.saveScan(results, arguments)
            print("Done! :)")
        except ValueError as e:
            logging.error(f"{str(e)}")
            print(
                "An error occurred during the scan. Please check your host and arguments."
            )
        except Exception as e:
            logging.error(f"{str(e)}")

def run():
    app = DeltaScan()
    app.main()
