from deltascan.core.exceptions import (DScanResultsParsingError)
from deltascan.core.config import (
    ADDED,
    CHANGED,
    REMOVED)
import copy
from deltascan.core.schemas import Diffs
from deltascan.core.exceptions import (DScanResultsSchemaException)
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
            DScanResultsSchemaException: If the diffs have an invalid schema.
        """
        try:
            Diffs().load(diffs)
        except (KeyError, ValidationError) as e:
            raise DScanResultsSchemaException(f"Invalid diff results schema: {str(e)}")

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
        try:
            scan_results = []
            for host in results.hosts:
                scan = {}
                scan["host"] = host.address
                scan["status"] = host.status
                scan["ports"] = []
                for s in host.services:
                    scan["ports"].append({
                        "portid": str(s._portid),
                        "proto": str(s._protocol),
                        "state": s._state,
                        "service": s.service,
                        "servicefp": "none" if isinstance(s.servicefp, str) and s.servicefp == "" else s.servicefp,
                        "service_product": "none" if isinstance(s.banner, str) and s.banner == "" else s.banner,
                    })

                scan["os"] = []
                try:
                    for _idx in range(3):
                        scan["os"].append(
                            host._extras["os"]["osmatches"][_idx]["osmatch"]["name"])
                except (KeyError, IndexError):
                    if len(scan["os"]) == 0:
                        scan["os"] = ["none"]
                    else:
                        pass

                scan["hops"] = []
                try:
                    for _hop in host._extras["trace"]["hops"]:
                        scan["hops"].append({_k: _hop[_k] for _k in ["ipaddr", "host"]})
                except (KeyError, IndexError):
                    if len(scan["hops"]) == 0:
                        scan["hops"] = ["none"]
                    else:
                        pass

                try:
                    scan["osfingerprint"] = host._extras["os"]["osfingerprints"][0]["fingerprint"]
                except (KeyError, IndexError):
                    scan["osfingerprint"] = "none"

                try:
                    scan["last_boot"] = host._extras["uptime"]["lastboot"]
                except KeyError:
                    scan["last_boot"] = "none"

                scan_results.append(scan)
            return scan_results
        except Exception as e:
            raise DScanResultsParsingError(f"An error occurred with the scan parser: {str(e)}")

