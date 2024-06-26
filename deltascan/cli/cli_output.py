# DeltaScan - Network scanning tool
#     Copyright (C) 2024 Logisek
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>

from deltascan.core.utils import (format_string)
from deltascan.core.output import Output
from deltascan.core.schemas import ReportScanFromDB, ReportDiffs
from deltascan.core.config import APP_DATE_FORMAT
from marshmallow import ValidationError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.box import SIMPLE_HEAD
from rich.columns import Columns
from deltascan.core.parser import Parser
import datetime


class CliOutput(Output):
    console: Console
    _display_title: str

    def __init__(self, data=None, verbose=False):
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
        self.verbose = verbose
        self._index_to_uuid_mapping = {}
        self.console = Console()

    def _validate_data(self, data):
        """
        Validates the input data and loads it into the appropriate
        format for display.

        Args:
            data (list): The input data to be validated and loaded.

        Raises:
            KeyError: If a required key is missing in the input data.
            TypeError: If the input data is of an unexpected type.
            ValidationError: If the input data fails validation.

        Returns:
            None
        """
        _valid_data = False
        if data == []:
            self._display_title = "No results found for the given arguments"
        else:
            try:
                # Process the data and load it into the appropriate format
                articulated_diffs = []
                self._display_title = "Differences"
                for diff in data:
                    articulated_diffs.append(
                        {
                            "date_from": diff["dates"][1],
                            "date_to": diff["dates"][0],
                            "diffs": Parser.diffs_to_output_format(diff),
                            "generic": diff["generic"],
                            "uuids": diff["uuids"]
                        })
                for d in articulated_diffs:
                    self.data.append(ReportDiffs().load(d))
                self._display = self._display_scan_diffs

                _valid_data = True
            except (KeyError, TypeError, ValidationError):
                pass

            if _valid_data is False:
                self._display_title = "Scan results"
                try:
                    self.data = ReportScanFromDB(many=True).load(data)
                    self._display = self._display_scan_results

                    _valid_data = True
                except (KeyError, ValidationError, TypeError) as e:
                    print(f"{str(e)}")

    def _display_scan_results(self):
        """
        Displays the scan results in a formatted table.

        Returns:
            list: A list of tables containing the scan results.
        """
        colors = {
            "col_1": "bright_yellow",
            "col_2": "rosy_brown",
            "col_3": "none",
            "col_4": "rosy_brown",
            "col_5": "bright_yellow",
            "col_6": "rosy_brown"
        }
        tables = []
        _counter = 1
        if self.verbose is False:
            _sup_table = Table(show_header=True)
            _sup_table.add_column("Index", style=colors["col_1"], no_wrap=False, width=10)
            _sup_table.add_column("Uid", style=colors["col_2"], no_wrap=False)
            _sup_table.add_column("Given Host/Subnet", style=colors["col_3"], no_wrap=False)
            _sup_table.add_column("Scanned Host", style=colors["col_1"], no_wrap=False, width=20)
            _sup_table.add_column("Status", style=colors["col_3"], no_wrap=False)
            _sup_table.add_column(
                "Profile", style=colors["col_4"], no_wrap=False, width=20)
            _sup_table.add_column("Date", style=colors["col_5"], no_wrap=False)
            _sup_table.add_column("Args", style=colors["col_5"], no_wrap=False, width=30)

        for scan in self.data:
            self._index_to_uuid_mapping[str(_counter)] = scan["uuid"]
            if self.verbose is True:
                table = Table(show_header=True)
                _status = self._print_color_depended_on_value(
                    scan['results']['status'])
                table.title = f"[dim]Host:       [/][rosy_brown]" \
                    f"{scan['host']}[/][dim]\n" \
                    f"Status:     [/][rosy_brown] {_status}[/][dim] \n" \
                    f"Date:       [/][rosy_brown]" \
                    f"{scan['created_at']}[/][dim] \n" \
                    f"Profile:    [/][rosy_brown]" \
                    f"{scan['profile_name']}[/][dim] \n" \
                    f"Arguments:  [/][rosy_brown]" \
                    f"{scan['arguments']}[/][dim] \n" \
                    f"Scan uid:   [/][rosy_brown]" \
                    f"{scan['uuid']}[/]"

                table.add_column("Port", style=colors["col_1"], no_wrap=False)
                table.add_column(
                    "Protocol",
                    style=colors["col_2"], no_wrap=False)
                table.add_column("State", style=colors["col_3"], no_wrap=False)
                table.add_column("Service", style=colors["col_4"])
                table.add_column("Service Fingerprint", style=colors["col_5"])
                table.add_column("Service product", style=colors["col_6"])

                for p in scan['results']["ports"]:
                    table.add_row(
                        str(p["portid"]),
                        p["protocol"],
                        self._print_color_depended_on_value(
                            self.__convert_to_string(p["state"]["state"])),
                        self.__convert_to_string(p["service_name"]),
                        self.__convert_to_string(p["servicefp"]),
                        self.__convert_to_string(p["service_product"]))

                table.border_style = "dim"
                table.title_justify = "left"
                table.caption_justify = "left"
                table.leading = False
                table.title_style = "frame"
                tables.append(table)
            else:
                _sup_table.add_row(
                    str(_counter),
                    scan["uuid"],
                    scan["host"],
                    scan["results"]["host"],
                    scan["results"]["status"],
                    scan["profile_name"],
                    scan["created_at"],
                    scan["arguments"]
                )
            _counter += 1

        if self.verbose is False:
            tables.append(_sup_table)

        return tables

    def _display_scan_diffs(self):
        """
        Displays the scan differences in a formatted table.

        Returns:
            list: A list of tables containing the scan differences.
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
            table.add_column(
                "[orange_red1]No results found "
                "for the given arguments[/]")
            return [table]

        for row in self.data:
            table = Table()
            table.title = f"[dim]Host:       [/][rosy_brown]" \
                          f"{self._print_generic_information_if_different(row['generic'][1]['host'], row['generic'][0]['host'])}[/]\n" \
                          f"[dim]Dates:      [/][rosy_brown]{self._print_is_today(row['date_from'])} " \
                          f"[red]->[/] {self._print_is_today(row['date_to'])}[/]\n" \
                          f"[dim]Scan uuids: [/][rosy_brown]{self._print_generic_information_if_different(row['uuids'][1], row['uuids'][0])}[/]\n" \
                          f"[dim]Profile:    [/][rosy_brown]" \
                          f"{self._print_generic_information_if_different(row['generic'][1]['profile_name'], row['generic'][0]['profile_name'])}[/]\n" \
                          f"[dim]Arguments:  [/][rosy_brown]" \
                          f"{self._print_generic_information_if_different(row['generic'][1]['arguments'], row['generic'][0]['arguments'])}[/]"
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
            table.leading = False
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
        new_list.append(self._print_color_depended_on_value(diff_dict["change"]))
        count = 1
        for k in diff_dict:
            if "field_" + str(count) in k:
                new_list.append(self._print_color_depended_on_value(diff_dict[k]))
                count = count + 1
        new_list.append(self._print_color_depended_on_value(diff_dict["from"]))
        new_list.append(f"[orange1]{self._print_color_depended_on_value(diff_dict['to'])}")
        return new_list

    def _display(self):
        print("No output to display ...")

    def display(self):
        """
        Displays the tables in a panel.

        Returns:
            None
        """
        tables = self._display()

        panel = Panel.fit(
            Columns(tables),
            box=SIMPLE_HEAD,
            title=self._display_title,
            padding=0
        )

        self.console.print(panel)
        return self._index_to_uuid_mapping

    @classmethod
    def profiles(cls, profiles):
        _profiles_table = Table(show_header=True)
        _profiles_table.add_column("Name", style="bright_yellow", no_wrap=False, width=50)
        _profiles_table.add_column("Arguments", style="rosy_brown", no_wrap=False)
        _profiles_table.add_column("Created at", style="bright_yellow", no_wrap=False, width=30)

        for profile in profiles:
            _profiles_table.add_row(profile["profile_name"], profile["arguments"], str(profile["created_at"]))

        panel = Panel.fit(Columns([_profiles_table]), title="Profiles", border_style="conceal", padding=(1, 2))
        console = Console()
        console.print(panel)

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
        elif isinstance(value, str) and value.isdigit():
            return f"[dark_sea_green2]{value}[/]"
        elif value == "removed":
            return f"[orange_red1]{value}[/]"
        elif value == "added":
            return f"[dark_sea_green2]{value}[/]"
        elif value == "changed":
            return f"[blue]{value}[/]"
        else:
            return f"{value}"

    @staticmethod
    def _print_generic_information_if_different(value_1, value_2):
        """
        Print the generic information if different.

        Args:
            value_1 (str): The first value to be compared.
            value_2 (str): The second value to be compared.

        Returns:
            None
        """
        if value_1 != value_2:
            return f"{value_1} [red]->[/] {value_2}"
        else:
            return f"{value_2}"

    @staticmethod
    def _print_is_today(date):
        """
        Print if the date is today.

        Args:
            date (datetime): The date to be checked.

        Returns:
            None
        """
        if datetime.datetime.strptime(date, APP_DATE_FORMAT).date() == datetime.datetime.now().date():
            return f"{date} [dark_sea_green2](Today)[/]"
        elif datetime.datetime.strptime(date, APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=1):
            return f"{date} [dark_sea_green2](Yesterday)[/]"
        elif datetime.datetime.strptime(date, APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=2):
            return f"{date} [dark_sea_green2](Day before yesterday)[/]"
        else:
            return f"{date}"
