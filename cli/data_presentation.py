from deltascan.core.utils import (diffs_to_output_format,
                                  format_string)
from deltascan.core.exceptions import (DScanResultsSchemaException,
                                       DScanExporterSchemaException)
from deltascan.core.output import Output
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs

from deltascan.core.config import APP_DATE_FORMAT
from marshmallow  import ValidationError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

import datetime

headerColor = "bold magenta"

class CliDisplay(Output):
    console: Console
    _display_title: str

    def __init__(self, data=None):
        """
        Initializes a new instance of the DataPresentation class.

        Args:
            data (list): The data to be presented.

        Returns:
            None
        """
        self.data = []
        if data is not None:
            self._validate_date(data)
        self.console = Console()
       
    def _validate_date(self, data):
        """
        Validates the given data and sets the appropriate display and title based on the data type.

        Args:
            data (list): The data to be validated.

        Returns:
            None

        Raises:
            KeyError: If a key is not found in the data.
            TypeError: If there is a type mismatch in the data.
            ValidationError: If the data fails validation.

        """
        _valid_data = False
        try:
            articulated_diffs = []
            for diff in data:
                articulated_diffs.append(
                    {"date_from": diff["dates"][1],
                     "date_to": diff["dates"][1],
                     "diffs": diffs_to_output_format(diff),
                     "generic": diff["generic"]})
            for d in articulated_diffs:
                self.data.append(ReportDiffs().load(d))
            self._display = self._display_scan_diffs
            self._display_title = "Differences"
            _valid_data = True
        except (KeyError, TypeError, ValidationError) as e:
            pass # print(f"{str(e)}")

        if _valid_data is False:
            try:
                self.data = ReportScanFromDB(many=True).load(data)
                self._display = self._display_scan_results
                self._display_title = "Scan results"
                _valid_data = True
            except (KeyError, ValidationError, TypeError) as e:
                print(f"{str(e)}")
       
    def _display_scan_results(self):
        """
        Display the scan list in a tabular format.

        Args:
            scanList (list): A list of dictionaries containing scan information.

        Returns:
            None
        """
        tables = []
        for scan in self.data:
            table = Table(show_header=True, header_style=headerColor)
            table.title = f"Host: {scan['host']}\nDate: {scan['created_at']} \nProfile: {scan['profile_name']} \nArguments: {scan['arguments']}"
            table.add_column("Port")
            table.add_column("State")
            table.add_column("Service")
            table.add_column("Service Fingerprint")
            table.add_column("Service product")

            for p in scan['results']["ports"]:
                # print(p)
                table.add_row(str(p["portid"]), p["state"], p["service"], p["servicefp"], p["service_product"])
            
            tables.append(table)
        return tables

    def _display_scan_diffs(self):
        """
        Display the scan list in a tabular format.

        Args:
            scanList (list): A list of dictionaries containing scan information.

        Returns:
            None
        """
        tables = []
        field_names = self._field_names_for_diff_results()

        for row in self.data:
            table = Table(show_header=True, header_style=headerColor)
            table.title = f"Host: {row['generic']['host']} - Profile: {row['generic']['profile_name']} - Arguments: {row['generic']['arguments']}"
            for f in field_names:
                table.add_column(format_string(f))
            lines = self._construct_exported_diff_data(row, field_names)
            for r in lines:
                fields = self._dict_diff_fields_to_list(r)
                table.add_row(*fields)
            tables.append(table)
        return tables
    
    def _dict_diff_fields_to_list(self, diff_dict):
        """
        Converts a dictionary of difference fields to a list.

        Args:
            diff_dict (dict): A dictionary containing the difference fields.

        Returns:
            list: A list containing the converted difference fields.

        """
        new_list = []
        new_list.append(self._print_is_today(diff_dict["date_from"]))
        new_list.append(self._print_is_today(diff_dict["date_to"]))
        count = 1
        for k in diff_dict:
            if "field_" + str(count) in k:
                new_list.append(self._print_color_depended_on_value(diff_dict[k]))
                count = count + 1
        new_list.append(self._print_color_depended_on_value(diff_dict["from"]))
        new_list.append(self._print_color_depended_on_value(diff_dict["to"]))
        return new_list

    def _display(self):
        raise NotImplementedError
    
    def display(self):
            """
            Displays the tables in a panel.

            Returns:
                None
            """
            tables = self._display()
            panel = Panel.fit(
                Columns(tables),
                title=self._display_title,
                border_style="magenta",
                title_align="left",
                padding=(1, 2))

            self.console.print(panel)

    @staticmethod
    def _print_color_depended_on_value(value):
        """
        Print the port state type.

        Args:
            value (str): The port state type to be printed.

        Returns:
            None
        """
        if value == "open":
            return f"[green]{value}"
        elif value == "closed":
            return f"[red]{value}"
        elif value == "filtered":
            return f"[red]{value}"
        elif value.isdigit():
            return f"[orange]{value}"
        else:
            return f"[blue]{value}"
    
    @staticmethod
    def _print_is_today(date):
        """
        Print if the date is today.

        Args:
            date (datetime): The date to be checked.

        Returns:
            None
        """
        if datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date():
            return f"{date} ([green]Today)"
        elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=1):
            return f"{date} ([green]Yesterday)"
        elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=2):
            return f"{date} ([green]Day before yesterday)"
        else:
            return f"{date}"