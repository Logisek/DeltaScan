import csv
from deltascan.core.exceptions import (DScanExporterSchemaException,
                                       DScanExporterFileExtensionNotSpecified,
                                       DScanExporterError,
                                       DScanExporterErrorProcessingData)
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, TableStyle
from reportlab.lib.units import mm
from marshmallow.exceptions  import ValidationError
import json
CSV = "csv"
PDF = "pdf"
import logging 

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class Reporter:
    def __init__(self, generic_data, data, filename):
        """
        Initializes a DScanExporter object.

        Args:
            generic_data (dict): The generic data for the export.
            data (list): The data to be exported.
            filename (str): The name of the export file.

        Raises:
            DScanExporterFileExtensionNotSpecified: If the file extension is not specified.
            DScanExporterSchemaException: If there is an issue with the data schema.

        """
        if filename.split(".")[-1] in [CSV, PDF]:
            self.filename = ''.join(filename.split('.')[:-1])
            self.file_extension = filename.split(".")[-1]
        else:
            raise DScanExporterFileExtensionNotSpecified("Please specify a file extension for the export file.")

        _valid_data = False

        self.data = []
        self.filename = filename
        self.general_data = generic_data
        # TODO: set diff export limit as entered by the user
        try:
            for d in data:
                self.data.append(ReportDiffs(many=True).load(d))
            if self.file_extension == CSV:
                self.export = self._diffs_to_csv
            elif self.file_extension == PDF:
                self.export = self._diffs_to_pdf
            else:
                raise DScanExporterFileExtensionNotSpecified("Could not determine file extension.")
            _valid_data = True
        except (KeyError, TypeError, ValidationError) as e:
            pass

        if _valid_data is False:
            try:
                self.data = ReportScanFromDB(many=True).load(data)
                if self.file_extension == CSV:
                    self.export = self._scans_to_csv
                elif self.file_extension == PDF:
                    self.export = self._scans_to_pdf
                else:
                    raise DScanExporterFileExtensionNotSpecified("Could not determine file extension.")
                _valid_data = True
            except (KeyError, ValidationError, TypeError) as e:
                logger.error(f"{str(e)}")
                raise DScanExporterSchemaException(f"{str(e)}")

    def _diffs_to_csv(self):
        """
        Export the differences to a CSV file.

        This method writes the differences stored in `self.data` to a CSV file.
        Each row in the CSV file represents a difference on a specific date.

        Returns:
            None
        """
        field_names = list(self.data[0][0].keys())
        with open(f"{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()
            for diffs_on_date in self.data:
                for row in diffs_on_date:
                    writer.writerow(row)

                writer.writerow({})

    def _scans_to_csv(self):
        """
        Export the scans data to a CSV file.

        This method writes the scans data to a CSV file with the specified filename and file extension.
        It uses the `csv.DictWriter` class to write the data as rows in the CSV file.

        Args:
            self (object): The instance of the class.

        Returns:
            None
        """
        field_names = list(self.data[0].keys())
        with open(f"{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()
            for row in self.data:
                writer.writerow(row)

    def _diffs_to_pdf(self):
        """
        Generate a PDF report based on the differences in the data.

        This method creates a PDF report containing the differences in the data.
        It uses the `report_schema` to structure the data in a table format and adds it to the PDF document.

        Raises:
            DScanExporterErrorProcessingData: If there is an error generating the PDF report.

        """
        try:
            doc = SimpleDocTemplate(f"{self.filename}.{self.file_extension}", pagesize=A4)
            style = TableStyle()
            style.add("VALIGN", (10, 10), (-1, -1), "MIDDLE")
            elements = []
            # Add title to the report
            elements.append(Paragraph("Differential Scan Report for " + self.general_data["host"]))
            elements.append(Paragraph(f'Nmap arguments: {self.general_data["arguments"]}'))
            elements.append(Paragraph(f"Profile: {self.general_data['profile_name']}"))

            report_schema = [
                ["From date", "To date", "Entity changed", "Entity value", "Change type", "From", "To"],
            ]
            
            for diffs_on_date in self.data:
                for d in diffs_on_date:
                    report_schema.append(
                        [
                            d["date_from"],
                            d["date_to"],
                            d["entity_name"],
                            d["entity_value"],
                            d["entity_change_type"],
                            d["entity_change_value_from"],
                            d["entity_change_value_to"]
                        ]
                    )
                report_schema.append(["", "", "", "", "", "", ""])

            table = Table(report_schema)
            table.setStyle(style)
            elements.append(table)
            doc.build(elements)

        except Exception as e: # TODO: remove generic exception
            print("Error generating PDF report: " + str(e))
            raise DScanExporterErrorProcessingData("Error generating PDF report: " + str(e))

    def _scans_to_pdf(self):
        """
        Converts the scans data to a PDF report.

        This method generates a PDF report using the scans data provided. It creates a table with the scan details
        including the date, host, arguments, profile, and results. The generated PDF report is saved with the
        specified filename and file extension.

        Raises:
            DScanExporterErrorProcessingData: If there is an error generating the PDF report.

        Returns:
            None
        """
        try:
            doc = SimpleDocTemplate(f"{self.filename}.{self.file_extension}", pagesize=A4)
            style = TableStyle()
            style.add("VALIGN", (10, 10), (-1, -1), "MIDDLE")
            print(self.data)
            elements = []
            # Add title to the report
            elements.append(Paragraph(f'Scan dump report'))

            report_schema = [
                ["Date", "Host", "Arguments", "Profile", "Results"], # TODO: modify results to be more articulate
            ]
            
            for scan in self.data:
                report_schema.append(
                    [
                        scan["created_at"],
                        scan["host"],
                        scan["arguments"],
                        scan["profile_name"],
                        scan["results"],
                    ]
                )
                report_schema.append(["", "", "", "", ""])

            table = Table(report_schema)
            table.setStyle(style)
            elements.append(table)
            doc.build(elements)

        except Exception as e:
            print("Error generating PDF report: " + str(e))
            raise DScanExporterErrorProcessingData("Error generating PDF report: " + str(e))

    def export(self):
        """
        Export the data.

        Raises:
            DScanExporterError: If there is an error reporting the data.
        """
        raise DScanExporterError("Error reporting data.")

