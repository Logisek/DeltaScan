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

from deltascan.core.exceptions import (AppExceptions)
from deltascan.core.utils import replace_nested_keys
from deltascan.core.config import (
    ADDED,
    CHANGED,
    REMOVED)
import copy
import xmltodict
from deltascan.core.schemas import Diffs
from marshmallow import ValidationError


class Parser:
    @classmethod
    def diffs_to_output_format(cls, diffs):
        """
        Convert the given diffs to a specific output format.

        Args:
            diffs (dict): The diffs to be converted.

        Returns:
            dict: The converted diffs in the specified output format.

        Raises:
            AppExceptions.DScanResultsSchemaException: If the diffs have an invalid schema.
        """
        try:
            Diffs().load(diffs)
        except (KeyError, ValidationError) as e:
            raise AppExceptions.DScanResultsSchemaException(f"Invalid diff results schema: {str(e)}")

        # Here, entity can be many things. In the future an entity, besides port
        # can be a service, a host, the osfingerpint.
        articulated_diffs = {
            ADDED: [],
            CHANGED: [],
            REMOVED: [],
        }

        articulated_diffs[ADDED] = cls._dict_diff_to_list_diff(diffs["diffs"], [], ADDED)
        articulated_diffs[CHANGED] = cls._dict_diff_to_list_diff(diffs["diffs"], [], CHANGED)
        articulated_diffs[REMOVED] = cls._dict_diff_to_list_diff(diffs["diffs"], [], REMOVED)

        return articulated_diffs

    @classmethod
    def _dict_diff_to_list_diff(cls, diff, depth: list, diff_type=CHANGED):
        """
        Recursively handles the differences in a dictionary and returns a list of handled differences.

        Args:
            diff (dict): The dictionary containing the differences.
            depth (list): The list representing the current depth in the
            dictionary.
            diff_type (str, optional): The type of difference to handle. Defaults to CHANGED.

        Returns:
            list: A list of handled differences.

        """
        handled_diff = []
        if (CHANGED in diff or ADDED in diff or REMOVED in diff) and isinstance(diff, dict):
            handled_diff.extend(cls._dict_diff_to_list_diff(diff[diff_type], depth, diff_type))
        else:
            for k, v in diff.items():
                tmpd = copy.deepcopy(depth)
                tmpd.append(k)

                if ("to" in v or "from" in v) and isinstance(v, dict):
                    tmpd.extend(["from", v["from"], "to", v["to"]])
                    handled_diff.append(tmpd)
                elif isinstance(v, dict):
                    handled_diff.extend(cls._dict_diff_to_list_diff(v, tmpd, diff_type))
                else:
                    tmpd.append(v)
                    handled_diff.append(tmpd)
        return handled_diff

    @classmethod
    def extract_port_scan_dict_results(cls, results):
        """
        Extracts the port scan results from the provided `results` object and returns a list of dictionaries.

        Args:
            results (object): The scan results object.

        Returns:
            list: A list of dictionaries containing the extracted scan results.

        Raises:
            Exception: If an error occurs during the scan parser.

        """
        results = replace_nested_keys(xmltodict.parse(results))["nmaprun"]
        try:
            try:
                args = results["args"]
            except KeyError:
                args = {}

            try:
                scaninfo = results["scaninfo"]
            except KeyError:
                scaninfo = {}

            try:
                start = results["start"]
            except KeyError:
                start = {}

            try:
                runstats = results["runstats"]
            except KeyError:
                runstats = {}

            scan_results = {
                "results": [],
                "args": args,
                "scaninfo": scaninfo,
                "start": start,
                "runstats": runstats,
            }

            if isinstance(results["host"], dict):
                results["host"] = [results["host"]]

            if isinstance(results["host"], list):
                for host in results["host"]:
                    _h = copy.deepcopy(host)

                    try:
                        if isinstance(host["address"], list):
                            for addr in host["address"]:
                                if addr["addrtype"] == "ipv4":
                                    _h["host"] = addr["addr"]
                                    break
                        else:
                            _h["host"] = host["address"]["addr"]
                    except (KeyError, IndexError, TypeError):
                        raise AppExceptions.DScanResultsParsingError("Could parse given host address")

                    _h["status"] = host["status"]["state"]

                    if "os" in host:
                        try:
                            _h["os"] = []
                            if isinstance(host["os"]["osmatch"], list):
                                for _, _match in enumerate(host["os"]["osmatch"][:3]):
                                    # print(_match["name"])
                                    _h["os"].append(_match["name"])
                            else:
                                _h["os"].append(host["os"]["osmatch"]["name"])

                        except (KeyError, IndexError, TypeError):
                            if len(_h["os"]) == 0:
                                _h["os"] = ["unknown"]
                            else:
                                pass

                        if "osfingerprint" in host["os"]:
                            try:
                                _h["osfingerprint"] = host["os"]["osfingerprint"]["fingerprint"]
                            except (KeyError, IndexError, TypeError):
                                _h["osfingerprint"] = "none"
                        else:
                            _h["osfingerprint"] = "none"

                    else:
                        _h["os"] = ["unknown"]
                        _h["osfingerprint"] = "none"

                    if "trace" in host:
                        try:
                            _h["hops"] = []
                            if isinstance(host["trace"]["hop"], list):
                                for _, _hop in enumerate(host["trace"]["hop"]):
                                    _h["hops"].append(_hop["ipaddr"])
                            else:
                                _h["hops"].append(host["trace"]["hop"]["ipaddr"])
                        except (KeyError, IndexError, TypeError):
                            if len(_h["hops"]) == 0:
                                _h["hops"] = ["unknown"]
                            else:
                                pass
                    else:
                        _h["hops"] = ["unknown"]

                    if "uptime" in host:
                        try:
                            _h["last_boot"] = host["uptime"]["lastboot"]
                        except (KeyError, IndexError, TypeError):
                            _h["last_boot"] = "none"
                    else:
                        _h["last_boot"] = "none"

                    # Remove all the fields that are not needed
                    _h.pop("starttime", None)
                    _h.pop("endtime", None)
                    _h.pop("times", None)

                    try:
                        if "port" in host["ports"] and isinstance(host["ports"]["port"], list):
                            try:
                                _ptmp = []

                                for p in _h["ports"]["port"]:
                                    p["servicefp"] = p["service"]["servicefp"] if "service" in p and "servicefp" in p["service"] else ""
                                    p["service_product"] = p["service"]["product"] if "service" in p and "product" in p["service"] else ""
                                    p["service_name"] = p["service"]["name"] if "service" in p and "name" in p["service"] else ""
                                    _ptmp.append(p)
                                _h["ports"] = _ptmp
                            except (KeyError, IndexError, TypeError):
                                _h["ports"] = []
                        elif "port" in host["ports"] and isinstance(host["ports"]["port"], dict):
                            try:
                                _ptmp = []
                                p = host["ports"]["port"]
                                p["servicefp"] = p["service"]["servicefp"] if "service" in p and "servicefp" in p["service"] else ""
                                p["service_product"] = p["service"]["product"] if "service" in p and "product" in p["service"] else ""
                                p["service_name"] = p["service"]["name"] if "service" in p and "name" in p["service"] else ""
                                _ptmp.append(p)
                                _h["ports"] = _ptmp
                            except (KeyError, IndexError, TypeError):
                                _h["ports"] = []
                    except KeyError:
                        _h["ports"] = []

                    scan_results["results"].append(_h)
            return scan_results
        except Exception as e:
            raise AppExceptions.DScanResultsParsingError(f"{str(e)}")
