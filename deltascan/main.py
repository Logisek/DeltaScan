import deltascan.core.scanner as scanner
import deltascan.core.store as store
import deltascan.cli.data_presentation as data_presentation
import deltascan.core.reports.pdf as pdf

from deltascan.core.exceptions import DScanInputValidationException
import logging
import os
import re

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class DeltaScan:
    """
    DeltaScan class represents the main program for performing scans, viewing results, and generating reports.
    """

    def __init__(self):
        self.store = store.Store()

    def checkRootPermissions(self):
        """
        Checks if the program is running with root permissions.
        """
        try:
            if os.getuid() != 0:
                raise PermissionError("You need root permissions to run this program.")
        except PermissionError as e:
            logger.error(e)
            print("You need root permissions to run this program.")
            exit()
        except Exception as e:
            logger.error(f"{str(e)}")

    def validate_host(self, value):
        """
        Validates the entered host.
        """
        try:
            if not re.match(r"^[a-zA-Z0-9.-/]+$", value):
                return "Invalid host. Please enter a valid IP address, domain name, or network address."
            return True
        except Exception as e:
            logger.error(f"{str(e)}")
            raise DScanInputValidationException(f"{str(e)}")

    def validate_arguments(self, value):
        """
        Validates the entered arguments.
        """
        try:
            if not re.match(r"^[a-zA-Z0-9\s-]+$", value):
                return "Invalid arguments. Please enter only alphanumeric characters, spaces, and hyphens."
            return True
        except Exception as e:
            logger.error(f"{str(e)}")
            raise DScanInputValidationException(f"{str(e)}")

    def port_scan(self, host, arguments):
        """
        Performs a scan based on the entered host and arguments.
        """
        
        try:
            self.validate_host(host)
            self.validate_arguments(arguments)

            results = scanner.scan(host, arguments)

            if results is None:
                raise ValueError("Wrong host or arguments.")

            self.store.save(results, arguments)
            print("Done! :)")
        except ValueError as e:
            logger.error(f"{str(e)}")
            print(
                "An error occurred during the scan. Please check your host and arguments."
            )
        except DScanInputValidationException as e:
            logger.error(f"{str(e)}")
        except Exception as e:
            logger.error(f"{str(e)}")

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
            logger.error(f"{str(e)}")

    def pdf_report(self):
        """
        Generates a PDF report based on the scan results.
        """
        try:
            results = self.dataHandler.getScanResults(1)
            pdf.generatePdfReport("default", results)
        except Exception as e:
            logger.error(f"{str(e)}")
