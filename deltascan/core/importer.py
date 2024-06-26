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

from deltascan.core.exceptions import (
    ImporterExceptions)
from deltascan.core.utils import (
    nmap_arguments_to_list)
from libnmap.parser import NmapParserException
from deltascan.core.parser import Parser
from deltascan.core.config import (APP_DATE_FORMAT, LOG_CONF, XML, CSV)
import csv
from datetime import datetime
import json
import logging


class Importer:
    def __init__(self, store, filename, logger=None):
        """
        Initialize the Importer object.

        Args:
            filename (str): The name of the import file.
            logger (Logger, optional): The logger object for logging import-related messages. Defaults to None.

        Raises:
            DScanImportFileExtensionError: If the file extension is not valid.
        """
        if filename is None:
            raise ImporterExceptions.DScanImportFileError("File is None")

        self.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        self._filename = filename
        self.store = store
        if filename.split(".")[-1] in [CSV, XML]:
            self._file_extension = filename.split(".")[-1]
            self._filename = filename[:-1*len(self._file_extension)-1]
            self._full_name = f"{self._filename}.{self._file_extension}"
        else:
            raise ImporterExceptions.DScanImportFileExtensionError("Please specify a valid file extension for the import file.")

        if self._file_extension == CSV:
            self.import_data = self._import_csv
        elif self._file_extension == XML:
            self.import_data = self._import_xml
        else:
            raise ImporterExceptions.DScanImportFileExtensionError("Please specify a valid file extension for the import file.")

    def _import_csv(self):
        """
        Imports CSV data from a file and saves the imported scans and arguments to the database.

        Returns the last N scans for the imported profile.

        Raises:
            DScanImportDataError: If the CSV data fails to import.
        """
        try:
            with open(self._full_name, 'r') as f:
                reader = csv.DictReader(f)         # read rows into a dictionary format
                _csv_data_to_dict = []
                for row in reader:                 # read a row as {column1: value1, column2: value2,...}
                    _row_data = {}
                    for (k, v) in row.items():     # go over each column name and value
                        _row_data[k] = v

                    _row_data["profile_name"], _row_data["profile_arguments"] = \
                        self._create_or_get_imported_profile(
                            _row_data["arguments"],
                            datetime.strptime(_row_data["created_at"], APP_DATE_FORMAT).timestamp())
                    _csv_data_to_dict.append(_row_data)
                for _row in _csv_data_to_dict:
                    _newly_imported_scans = self.store.save_scans(
                        _row["profile_name"],
                        _row["host"],  # Subnet
                        [json.loads(_row["results"])],
                        created_at=_row["created_at"])

                _new_uuids_list = [_s.uuid for _s in list(_newly_imported_scans)]
                last_n_scans = self.store.get_filtered_scans(
                    uuid=_new_uuids_list)

                return last_n_scans
        except Exception as e:
            self.logger.error(f"Failed importing CSV data: {str(e)}")
            raise ImporterExceptions.DScanImportDataError(f"{str(e)}")

    def _import_xml(self):
        """
        Imports XML data from a file and saves the imported scans and arguments to the database.

        Returns the last N scans for the imported profile.

        Raises:
            DScanImportDataError: If the XML data fails to parse.
        """
        try:
            _r = self.load_results_from_file()

            _parsed = Parser.extract_port_scan_dict_results(_r)
            _host = _parsed["args"].split(" ")[-1]

            _profile_name, _ = \
                self._create_or_get_imported_profile(
                    _parsed["args"], _parsed["start"])

            _newly_imported_scans = self.store.save_scans(
                _profile_name,
                _host,  # Subnet
                _parsed["results"],
                created_at=datetime.fromtimestamp(int(
                    _parsed["runstats"]["finished"]["time"])).strftime(
                        APP_DATE_FORMAT) if "finished" in _parsed["runstats"] else None)

            _new_uuids_list = [_s.uuid for _s in list(_newly_imported_scans)]

            last_n_scans = self.store.get_filtered_scans(
                uuid=_new_uuids_list)

            return last_n_scans
        except NmapParserException as e:
            self.logger.error(f"Failed parsing XML data: {str(e)}")
            raise ImporterExceptions.DScanImportDataError(f"{str(e)}")

    def load_results_from_file(self):
        """
        Load results from a file and parse them using NmapParser.

        Args:
            filename (str): The path to the file containing the results.

        Returns:
            NmapReport: The parsed Nmap report.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            IOError: If there is an error reading the file.

        """
        data = None
        with open(self._full_name, 'r') as file:
            data = file.read()

        return data

    def _create_or_get_imported_profile(self, imported_args, new_profile_date=str(datetime.now())):
        """
        Creates a new profile or retrieves an existing profile based on the imported arguments.

        Args:
            imported_args (str): The imported arguments.
            new_profile_date (str, optional): The date for the new profile. Defaults to the current date and time.

        Returns:
            tuple: A tuple containing the profile name and arguments.

        """
        _imported_args = nmap_arguments_to_list(imported_args)

        _profile_found_in_db = False
        for _pr in self.store.get_profiles():
            _pr_args = [_arg for _arg in _pr["arguments"].split(" ") if _arg != "" and _arg != " "]
            if self._compare_nmap_arguments(_imported_args, _pr_args):
                _profile_name = _pr["profile_name"]
                _profile_args = _pr["arguments"]
                _profile_found_in_db = True
                break

        if not _profile_found_in_db:
            _profile_name = f"IMPORTED_{new_profile_date}"
            _profile_args = " ".join(_imported_args)
            _ = self.store.save_profiles({f"IMPORTED_{new_profile_date}": {"arguments": " ".join(_imported_args)}})

        return (_profile_name, _profile_args)

    @staticmethod
    def _compare_nmap_arguments(imported_args, profile_args):
        """
        Compare the imported Nmap arguments with the profile arguments.

        Args:
            imported_args (list): The list of Nmap arguments imported from a file.
            profile_args (list): The list of Nmap arguments defined in the profile.

        Returns:
            bool: True if the imported arguments match the profile arguments, False otherwise.
        """
        return len(imported_args) == len(profile_args) and all([arg in profile_args for arg in imported_args])

    def import_data(self):
        # Add your code here to import the data
        self.logger.error("Error importing file: 'import_data' not implemented")
        raise ImporterExceptions.DScanImportError("Something wrong importing file.")

    @property
    def full_name(self):
        self._full_name = f"{self._filename}.{self._file_extension}"

    @property
    def filename(self):
        """
        Get the name of the import file.

        Returns:
            str: The name of the import file.
        """
        return self._filename

    @filename.setter
    def filename(self, value):
        """
        Set the name of the import file.

        Args:
            value (str): The name of the import file.
        """
        self._file_extension = value.split(".")[-1]
        self._filename = value[:-1*len(self._file_extension)-1]
        self._full_name = f"{self._filename}.{self._file_extension}"
