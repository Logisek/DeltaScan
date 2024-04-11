from deltascan.core.nmap.libnmap_wrapper import LibNmapWrapper
from deltascan.core.config import LOG_CONF

import logging

class Scanner:
    """
    The Scanner class is responsible for performing scans on specified targets using provided scan arguments.
    """

    @classmethod
    def scan(cls, target=None, scan_args=None, ui_context=None, logger=None):
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
            scan_results = LibNmapWrapper.scan(target, scan_args, ui_context, logger=cls.logger)
            scan_results = cls._extract_port_scan_dict_results(scan_results)

            if scan_results is None:
                raise ValueError("Failed to parse scan results")

            return scan_results

        except Exception as e:
            cls.logger.error(f"An error ocurred with nmap: {str(e)}")

    @classmethod
    def _extract_port_scan_dict_results(cls, results):
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
            cls.logger.error(f"An error occurred with the scan parser: {str(e)}")
