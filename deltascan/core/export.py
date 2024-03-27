import csv
from deltascan.core.exceptions import (DScanExporterSchemaException,
                                       DScanExporterFileExtensionNotSpecified,
                                       DScanExporterError,
                                       DScanExporterErrorProcessingData)
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs
from deltascan.core.utils import format_string
from deltascan.core.output import Output

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, TableStyle
from reportlab.lib.units import mm
from marshmallow.exceptions  import ValidationError
import json
import logging 

CSV = "csv"
PDF = "pdf"


logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class Exporter(Output):
    def __init__(self, data, filename):
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
            raise DScanExporterFileExtensionNotSpecified("Please specify a valid file extension for the export file.")

        _valid_data = False

        self.data = []
        # TODO: set diff export limit as entered by the user
        try:
            for d in data:
                self.data.append(ReportDiffs().load(d))
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
        field_names = self._field_names_for_diff_results()
        with open(f"{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()

            for row in self.data:
                lines = self._construct_exported_diff_data(row, field_names)
                for r in lines:
                    writer.writerow(r)

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
            style.add("VALIGN", (5, 10), (-1, -1), "MIDDLE")
            elements = []
            elements.append(Paragraph(f'Diff report'))
            field_names = self._field_names_for_diff_results()
            for diffs_on_date in self.data:
                elements.append(Paragraph(f"Differential Scan Report for {diffs_on_date['generic']['host']}"))
                elements.append(Paragraph(f"Nmap arguments: {diffs_on_date['generic']['arguments']}"))
                elements.append(Paragraph(f"Profile: {diffs_on_date['generic']['profile_name']}"))
                lines = self._construct_exported_diff_data(diffs_on_date, field_names)
                report_schema = [[format_string(field_name) for field_name in field_names]]
                for r in lines:
                    report_schema.append([*self._dict_diff_fields_to_list(r)])

                report_schema.append(["" for _ in range(len(field_names))])
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
            style.add("VALIGN", (10, 10), (-10, -10), "MIDDLE")
            elements = []
            elements.append(Paragraph(f'Scan dump report'))
            
            for scan in self.data: 
                elements.append(Paragraph(f"Differential Scan Report for {scan['host']}"))
                elements.append(Paragraph(f"Nmap arguments: {scan['arguments']}"))
                elements.append(Paragraph(f"Profile: {scan['profile_name']}"))
                elements.append(Paragraph(f"Profile: {scan['created_at']}"))
                report_schema = [
                    ["Port", "State", "Service", "Service FP", "Service Product"]
                ]
                for port in scan["results"]["ports"]:
                    report_schema.append(
                        [
                            port["portid"],
                            port["state"],
                            port["service"],
                            port["servicefp"],
                            port["service_product"],
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

    def _dict_diff_fields_to_list(self, diff_dict):
        """
        Convert a dictionary of difference fields to a list.

        Args:
            diff_dict (dict): A dictionary containing difference fields.

        Returns:
            list: A list containing the values of the difference fields.

        """
        new_list = []
        new_list.append(diff_dict["date_from"])
        new_list.append(diff_dict["date_to"])
        count = 1
        for k in diff_dict:
            if "field_" + str(count) in k:
                new_list.append(diff_dict[k])
                count = count + 1
        new_list.append(diff_dict["from"])
        new_list.append(diff_dict["to"])
        return new_list


    def export(self):
        """
        Export the data.

        Raises:
            DScanExporterError: If there is an error reporting the data.
        """
        raise DScanExporterError("Error reporting data.")

