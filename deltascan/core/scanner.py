from deltascan.core.nmap.libnmap_wrapper import LibNmapWrapper
import logging

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

class Scanner:
    """
    Attributes:
        scanner (nmap3.Nmap): The nmap scanner object.
        target (str): The target IP address or hostname.
        args (str): The arguments to be passed to the nmap scan command.
        timeout (int): The timeout value for the scan command.

    Methods:
        scanCommand(target, arg, args=None, timeout=None): Performs the port scan command and returns the scan results.
        dataManipulator(xml): Manipulates the XML scan results and returns a list of dictionaries representing the scan data.
    """    
    @classmethod
    def scan(cls, target=None, scan_args=None, ui_context=None):
        """
        Perform a scan on the specified target using the given arguments.

        Args:
            target (str): The target to scan.
            scan_args (str): The arguments to pass to the scanner.

        Returns:
            dict: The scan results.
        """
        if target is None or scan_args is None:
            raise ValueError("Target and scan arguments must be provided")

        if "-vv" not in scan_args:
            scan_args = "-vv " + scan_args

        try:
            scan_results = LibNmapWrapper.scan(target, scan_args, ui_context)
            scan_results = cls._extract_port_scan_dict_results(scan_results)

            if scan_results is None:
                raise ValueError("Failed to parse scan results")

            return scan_results

        except Exception as e:
            logging.error(f"An error ocurred with nmap: {str(e)}")

    @classmethod
    def _extract_port_scan_dict_results(self, results):
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
                        "state": s._state,
                        "service": s.service,
                        "servicefp": "none" if isinstance(s.servicefp, str) and s.servicefp == "" else s.servicefp,
                        "service_product": "none" if isinstance(s.banner, str) and s.servicefp == "" else s.banner,
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
            logging.error(f"An error occurred with the scan parser: {str(e)}")
            print("An error has occurred, check error.log")
