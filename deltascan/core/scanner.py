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

from deltascan.core.nmap.libnmap_wrapper import LibNmapWrapper
from deltascan.core.config import LOG_CONF
from deltascan.core.parser import Parser
import logging


class Scanner:
    """
    The Scanner class is responsible for performing scans on specified targets using provided scan arguments.
    """
    @classmethod
    def scan(cls, target=None, scan_args=None, ui_context=None, logger=None, name=None, _cancel_evt=None):
        """
        Perform a scan on the specified target using the provided scan arguments.

        Args:
            target (str): The target to scan.
            scan_args (str): The arguments to pass to the scan.
            ui_context: The UI context.
            logger: The logger to use for logging.

        Returns:
            dict: The scan results.

        Raises:
            ValueError: If target or scan_args are not provided.
            ValueError: If failed to parse scan results.
        """
        cls.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        if target is None or scan_args is None:
            raise ValueError("Target and scan arguments must be provided")

        if "-vv" not in scan_args:
            scan_args = "-vv " + scan_args

        try:
            scan_results = LibNmapWrapper.scan(target, scan_args, ui_context, logger=cls.logger, name=name, _cancel_evt=_cancel_evt)
            scan_results = Parser.extract_port_scan_dict_results(scan_results)

            if scan_results is None:
                raise ValueError("Failed to parse scan results")

            return scan_results

        except Exception as e:
            cls.logger.error(f"An error ocurred with nmap: {str(e)}")
