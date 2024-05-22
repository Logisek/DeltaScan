import csv
from deltascan.core.exceptions import (DScanExporterSchemaException,
                                       DScanExporterFileExtensionNotSpecified,
                                       DScanExporterErrorProcessingData)
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs
# from deltascan.core.utils import format_string
from deltascan.core.output import Output
from jinja2 import Template
import pdfkit
from deltascan.core.config import (LOG_CONF, CSV, HTML, PDF)
from marshmallow.exceptions import ValidationError
import json
import logging
import os


class Exporter(Output):
    def __init__(self, data, filename, template=None, single=False, logger=None):
        """
        Initialize the Exporter object.

        Args:
            data (list): The data to be exported.
            filename (str): The name of the export file.
            template (str, optional): The path to the template file. Defaults to None.
            single (bool, optional): Whether to export as a single diff/scan or multiple. Defaults to False.
            logger (Logger, optional): The logger object. Defaults to None.

        Raises:
            DScanExporterFileExtensionNotSpecified: If the file extension is not specified or invalid.
            DScanExporterSchemaException: If there is an error with the data schema.

        """
        self.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        if filename.split(".")[-1] in [CSV, PDF, HTML]:
            self.file_extension = filename.split(".")[-1]
            self.filename = filename[:-1*len(self.file_extension)-1].replace('/', '_')
        else:
            raise DScanExporterFileExtensionNotSpecified("Please specify a valid file extension for the export file.")

        _valid_data = False

        self.data = []
        # TODO: set diff export limit as entered by the user
        try:
            for d in data:
                self.data.append(ReportDiffs().load(d))
            if self.file_extension == CSV:
                if single:
                    self.export = self._single_diffs_to_csv
                else:
                    self.export = self._diffs_to_csv
            elif self.file_extension == PDF:
                self.export = self._diffs_to_pdf
            elif self.file_extension == HTML:
                self.export = self._diffs_to_html
            else:
                raise DScanExporterFileExtensionNotSpecified("Could not determine file extension.")
            _valid_data = True
            # TODO: remove default templates
            self.template_file = template if template is not None else os.getcwd() + "/deltascan/core/templates/diffs_report.html"
        except (KeyError, TypeError, ValidationError):
            pass

        if _valid_data is False:
            try:
                self.data = ReportScanFromDB(many=True).load(data)
                if self.file_extension == CSV:
                    if single:
                        self.export = self._single_scans_to_csv
                    else:
                        self.export = self._scans_to_csv
                elif self.file_extension == PDF:
                    self.export = self._scans_to_pdf
                elif self.file_extension == HTML:
                    self.export = self._scans_to_html
                else:
                    raise DScanExporterFileExtensionNotSpecified("Could not determine file extension.")
                _valid_data = True
                # TODO: remove default templates
                self.template_file = template if template is not None else os.getcwd() + "/deltascan/core/templates/scans_report.html"
            except (KeyError, ValidationError, TypeError) as e:
                self.logger.error(f"{str(e)}")
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
        field_names.insert(0, "date_to")
        field_names.insert(0, "date_from")
        with open(f"{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()

            for row in self.data:
                lines = self._construct_exported_diff_data(row, field_names)
                for r in lines:
                    writer.writerow(r)

    def _single_diffs_to_csv(self):
        """
        Export the differences to a CSV file.

        This method writes the differences stored in `self.data` to a CSV file.
        Each row in the CSV file represents a difference on a specific date.

        Returns:
            None
        """
        field_names = self._field_names_for_diff_results()
        field_names.insert(0, "date_to")
        field_names.insert(0, "date_from")
        for row in self.data:
            lines = self._construct_exported_diff_data(row, field_names)
            with open(f"{row['generic']['host']}_{row['uuids'][1]}_{row['uuids'][0]}_{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=field_names)
                writer.writeheader()
                for r in lines:
                    writer.writerow(r)

    def _scans_to_csv(self):
        """
        Export the scans data to a CSV file.

        This method writes the scans data to a CSV file with the specified filename and file extension.
        It uses the `csv.DictWriter` class to write the data as rows in the CSV file.

        Returns:
            None
        """
        field_names = list(self.data[0].keys())
        with open(f"{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_names)
            writer.writeheader()
            for row in self.data:
                row["results"] = json.dumps(row["results"])
                writer.writerow(row)

    def _single_scans_to_csv(self):
        """
        Export the scans data to a CSV file.

        This method writes the scans data to a CSV file with the specified filename and file extension.
        It uses the `csv.DictWriter` class to write the data as rows in the CSV file.

        Returns:
            None
        """
        for _scan in self.data:
            field_names = list(_scan.keys())
            with open(f"{_scan['host']}_{_scan['uuid']}_{self.filename}.{self.file_extension}", 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=field_names)
                writer.writeheader()
                _scan["results"] = json.dumps(_scan["results"])
                writer.writerow(_scan)

    def _diffs_report_to_html_string(self):
        """
        Generate a PDF report based on the differences in the data.

        This method creates a PDF report containing the differences in the data.
        It uses the `report_schema` to structure the data in a table format and adds it to the PDF document.

        Raises:
            DScanExporterErrorProcessingData: If there is an error generating the PDF report.

        """
        try:
            with open(self.template_file, 'r') as file:
                html_string = file.read()

            field_names = self._field_names_for_diff_results()
            _data_for_template = []
            for diffs_on_date in self.data:
                # These are the fields for the HTML template
                # TODO: create a specific function to handle these comparisons
                _augmented_diff = {
                    "date_from": diffs_on_date["date_from"],
                    "date_to": diffs_on_date["date_to"],
                    "uuids": diffs_on_date["uuids"],
                    "profile_name": diffs_on_date["generic"][0]["profile_name"] if
                    diffs_on_date["generic"][0]["profile_name"] == diffs_on_date["generic"][1]["profile_name"] else
                    f'{diffs_on_date["generic"][0]["profile_name"]} ->  {diffs_on_date["generic"][1]["profile_name"]}',
                    "arguments": diffs_on_date["generic"][0]["arguments"] if
                    diffs_on_date["generic"][0]["arguments"] == diffs_on_date["generic"][1]["arguments"] else
                    f'{diffs_on_date["generic"][0]["arguments"]} ->  {diffs_on_date["generic"][1]["arguments"]}',
                    "host": diffs_on_date["generic"][0]["host"] if
                    diffs_on_date["generic"][0]["host"] == diffs_on_date["generic"][1]["host"] else
                    f'{diffs_on_date["generic"][0]["host"]} ->  {diffs_on_date["generic"][1]["host"]}',
                    "_data": []
                }
                lines = self._construct_exported_diff_data(diffs_on_date, field_names)
                # report_schema = [[format_string(field_name) for field_name in field_names]]

                _diffs_for_two_scans = []
                for r in lines:
                    _diffs_for_two_scans.append([*self._dict_diff_fields_to_list(r)])
                _augmented_diff["_data"] = _diffs_for_two_scans
                _data_for_template.append(_augmented_diff)

            data = {
                'field_names': field_names,
                'diffs': _data_for_template,
                'section_title': 'Report for company',
                "section_info": "Information"
            }

            template = Template(html_string)
            report = template.render(data)
            return report
        except Exception as e:  # TODO: remove generic exception
            self.logger.error("Error generating PDF report: " + str(e))
            raise DScanExporterErrorProcessingData("Error generating PDF report: " + str(e))

    def _scans_report_to_html_string(self):
        """
        Generates an HTML report based on the provided template file and data.

        Returns:
            str: The generated HTML report as a string.

        Raises:
            DScanExporterErrorProcessingData: If there is an error generating the HTML report.
        """
        try:
            with open(self.template_file, 'r') as file:
                html_string = file.read()
            data = {
                'field_names': ["Port", "State", "Service", "Service FP", "Service Product"],
                'scans': self.data,
                'section_title': 'Report for company',
                "section_info": "Information"
            }

            template = Template(html_string)
            report = template.render(data)

            return report
        except Exception as e:
            self.logger.error("Error generating HTML report: " + str(e))
            raise DScanExporterErrorProcessingData("Error generating HTML report: " + str(e))

    def _diffs_to_html(self):
        """
        Converts the diffs report to an HTML string and writes it to a file.
        """
        _html_str = self._diffs_report_to_html_string()
        self.__write_to_file(_html_str)

    def _scans_to_html(self):
        """
        Converts the scans report to an HTML string and writes it to a file.
        """
        _html_str = self._scans_report_to_html_string()
        self.__write_to_file(_html_str)

    def _diffs_to_pdf(self):
        """
        Converts an HTML report to a PDF file.
        """
        _html_str = self._diffs_report_to_html_string()
        pdfkit.from_string(_html_str, f"{self.filename}.{self.file_extension}")

    def _scans_to_pdf(self):
        """
        Converts an HTML report to a PDF file.
        """
        _html_str = self._scans_report_to_html_string()
        pdfkit.from_string(_html_str, f"{self.filename}.{self.file_extension}")

    def __write_to_file(self, report, prefix=""):
        """
        Writes the given data to a file with the specified filename and file extension.

        Args:
            data: The data to be written to the file.

        Returns:
            None
        """
        # TODO: Set prefix much earlier. Create a dedicated method to construct file names
        with open(f"{self.filename}.{self.file_extension}", 'w') as file:
            file.write(report)

    def _dict_diff_fields_to_list(self, diff_dict):
        """
        Convert a dictionary of difference fields to a list.

        Args:
            diff_dict (dict): A dictionary containing difference fields.

        Returns:
            list: A list containing the values of the difference fields.

        """
        new_list = []
        new_list.append(self.__break_str_in_lines(diff_dict["change"]))
        count = 1
        for k in diff_dict:
            if "field_" + str(count) in k:
                new_list.append(self.__break_str_in_lines(diff_dict[k]))
                count = count + 1
        new_list.append(self.__break_str_in_lines(diff_dict["from"]))
        new_list.append(self.__break_str_in_lines(diff_dict["to"]))
        return new_list

    @staticmethod
    def __break_str_in_lines(s, line_width=20):
        """
        Breaks a string into multiple lines with a specified line width.

        Args:
            s (str): The input string to be broken into lines.
            line_width (int, optional): The maximum width of each line. Defaults to 40.

        Returns:
            str: The input string broken into lines.

        """
        _ls = []
        if isinstance(s, list):
            s = " ".join(s)
        for i in range(0, len(s), line_width):
            _ls.append(s[i:i+line_width])
        return '<br/>'.join(_ls)

    def export(self):
        """
        Export the data.

        Raises:
            DScanExporterError: If there is an error reporting the data.
        """
        raise NotImplementedError("Method 'export' not implemented.")
