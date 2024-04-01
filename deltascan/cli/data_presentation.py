from deltascan.core.utils import (diffs_to_output_format,
                                  format_string)
from deltascan.core.output import Output
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs

from deltascan.core.config import APP_DATE_FORMAT
from marshmallow  import ValidationError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

import json
import datetime

class CliOutput(Output):
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
            self._validate_data(data)
        self.console = Console()
       
    def _validate_data(self, data):
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
                     "date_to": diff["dates"][0],
                     "diffs": diffs_to_output_format(diff),
                     "generic": diff["generic"],
                     "uuids": diff["uuids"]})
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
        colors = {
            "col_1": "bright_yellow",
            "col_2": "none",
            "col_3": "bright_yellow",
            "col_4": "rosy_brown",
            "col_5": "bright_yellow"
        }
        tables = []

        for scan in self.data:
            table = Table(show_header=True)
            table.title = f"[dim]Host:       [/][rosy_brown]{scan['host']}[/][dim]\n" \
                    f"Status:     [/][rosy_brown]{self._print_color_depended_on_value(scan['results']['status'])}[/][dim] \n" \
                    f"Date:       [/][rosy_brown]{scan['created_at']}[/][dim] \n" \
                    f"Profile:    [/][rosy_brown]{scan['profile_name']}[/][dim] \n" \
                    f"Arguments:  [/][rosy_brown]{scan['arguments']}[/][dim] \n" \
                    f"Scan uid:   [/][rosy_brown]{scan['uuid']}[/]"
            
            table.add_column("Port", style=colors["col_1"], no_wrap=True)
            table.add_column("State", style=colors["col_2"], no_wrap=True)
            table.add_column("Service", style=colors["col_3"])
            table.add_column("Service Fingerprint", style=colors["col_4"])
            table.add_column("Service product", style=colors["col_5"])

            for p in scan['results']["ports"]:
                table.add_row(
                    str(p["portid"]),
                    self._print_color_depended_on_value(self.__convert_to_string(p["state"]["state"])),
                    self.__convert_to_string(p["service"]),
                    self.__convert_to_string(p["servicefp"]),
                    self.__convert_to_string(p["service_product"]))
            table.border_style = "dim"
            table.title_justify = "left"
            table.caption_justify = "left"
            table.leading  = False
            table.title_style = "frame"

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
        colors = [
            "bright_yellow",
            "rosy_brown"
        ]
        tables = []
        field_names = self._field_names_for_diff_results()
        # Treat spaces between text more cleverly. Use the Python -> print API
        if len(self.data) == 0:
            table = Table()
            table.add_column("[orange_red1]No differences found for the given arguments[/]")
            return [table]

        for row in self.data:
            table = Table()
            table.title = f"[dim]Host:       [/][rosy_brown]{row['generic']['host']}[/]\n" \
                        f"[dim]Dates:      [/][rosy_brown]{self._print_is_today(row['date_from'])} " \
                        f"-> {self._print_is_today(row['date_to'])}[/]\n" \
                        f"[dim]Scan uuids: [/][rosy_brown]{row['uuids'][1]} -> {row['uuids'][0]}[/]\n" \
                        f"[dim]Profile:    [/][rosy_brown]{row['generic']['profile_name']}[/]\n" \
                        f"[dim]Arguments:  [/][rosy_brown]{row['generic']['arguments']}[/]"
            c = 0
            _w = 20
            for _, f in enumerate(field_names):
                if "field" in f:
                    _w = 35
                else:
                    _w = 53

                table.add_column(format_string(f), style=colors[c], no_wrap=True, width=_w)
                c = 0 if c >= len(colors)-1 else c+1
            lines = self._construct_exported_diff_data(row, field_names)

            for r in lines:
                fields = self._dict_diff_fields_to_list(r)
                table.add_row(*fields)
            table.border_style = "dim"
            table.title_justify = "left"
            table.caption_justify = "left"
            table.leading  = False
            table.title_style = "frame"
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
        count = 1
        for k in diff_dict:
            if "field_" + str(count) in k:
                new_list.append(self._print_color_depended_on_value(diff_dict[k]))
                count = count + 1
        new_list.append(self._print_color_depended_on_value(diff_dict["from"]))
        new_list.append(f"[orange1]{self._print_color_depended_on_value(diff_dict['to'])}")
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
                border_style ="conceal",
                padding=(1, 2))

            self.console.print(panel)

    @staticmethod
    def __convert_to_string(value):
        """
        Converts the given value to a string if it is not already one.

        Args:
            value: The value to be converted.

        Returns:
            str: The converted value as a string.
        """
        if not isinstance(value, str):
            return str(value)
        return value

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
            return f"[dark_sea_green2]{value}[/]"
        elif value == "closed":
            return f"[orange_red1]{value}[/]"
        elif value == "down":
            return f"[orange_red1]{value}[/]"
        elif value == "filtered":
            return f"[dark_orange3]{value}[/]"
        elif value.isdigit():
            return f"[pale_turquoise1]{value}[/]"
        else:
            return f"{value}"

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
            return f"{date} [dark_sea_green2](Today)[/]"
        elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=1):
            return f"{date} [dark_sea_green2](Yesterday)[/]"
        elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=2):
            return f"{date} [dark_sea_green2](Day before yesterday)[/]"
        else:
            return f"{date}"