import nmap3
import logging

logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

class Scanner:
    """
    A facade class for performing port scanning using nmap.

    Attributes:
        scanner (nmap3.Nmap): The nmap scanner object.
        target (str): The target IP address or hostname.
        args (str): The arguments to be passed to the nmap scan command.
        timeout (int): The timeout value for the scan command.

    Methods:
        scanCommand(target, arg, args=None, timeout=None): Performs the port scan command and returns the scan results.
        dataManipulator(xml): Manipulates the XML scan results and returns a list of dictionaries representing the scan data.
    """
    target = ""
    scan_args = ""
    def __init__(self, *args, **kwargs):
        self.nmap_scanner = nmap3.Nmap()
        self.nmap_scanner.as_root = True
    
    def scan(self, target, scan_args):
        """
        Perform a scan on the specified target using the given arguments.

        Args:
            target (str): The target to scan.
            scan_args (str): The arguments to pass to the scanner.

        Returns:
            dict: The scan results.
        """
        if "-vv" not in scan_args:
            scan_args = "-vv " + scan_args

        try:
            scan_results = self._extract_port_scan_results(
               self.nmap_scanner.scan_command(target, scan_args) 
            )

            if scan_results is None:
                raise ValueError("dataManipulator function returned None")

            return scan_results

        except Exception as e:
            logging.error(f"An error ocurred with nmap: {str(e)}")

    def _extract_port_scan_results(self, raw_scan_results_xml):
        """
        Manipulates the XML scan results and returns a list of dictionaries representing the scan data.

        Args:
            raw_scan_results_xml (str): The XML scan results.

        Returns:
            list: A list of dictionaries representing the scan data.
        """
        try:
            scan_results = []
            for host in raw_scan_results_xml.findall("host"):
                host_data = {}
                host_data["host"] = host.find("address").attrib["addr"] if host.findall("address") else "unknown"
                host_data["status"] = host.find("status").attrib["state"] if host.findall("status") else "unknown"
                host_data["ports"] = []

                if host.find("ports"):
                    for port in host.find("ports").findall("port"):
                        portData = {}
                        portData["portid"] = port.attrib["portid"]
                        portData["state"] = port.find("state").attrib["state"] if port.findall("state") else "unknown"
                        portData["service"] = port.find("service").attrib["name"] if port.findall("service") else "unknown"
                        portData["servicefp"] = port.find("service").attrib["servicefp"] if "servicefp" in port.find("service").attrib else "unknown"
                        portData["service_product"] = port.find("service").attrib.get("product", "unknown") if port.findall("service") else "unknown"

                        host_data["ports"].append(portData)
                
                host_data["os"] = []
                if host.find("os"):
                    count = 0
                    for os in host.find("os").findall("osmatch"):
                        if count >= 3:
                            break
                        host_data["os"].append(os.attrib["name"])
                        count += 1
                    host_data["osfingerprint"] = host.find("os").find(
                        "osfingerprint").attrib["fingerprint"] if host.find("os").findall("osfingerprint") else "unknown"
                else:
                    host_data["os"] = []
                    host_data["osfingerprint"] = "unknown"
                
                if host.find("uptime"):
                    host_data["last_boot"] = host.find("uptime").find(
                        "uptime").attrib["lastboot"] if host.find("uptime").findall("uptime") else "unknown"
                else:
                    host_data["last_boot"] = "unknown"
                
                traces = []
                if host.find("trace"):
                    for hop in host.find("trace").findall("hop"):
                        traces.append(hop.attrib["ipaddr"])
                host_data["traces"] = traces
                
                scan_results.append(host_data)
            return scan_results

        except Exception as e:
            logging.error(f"An error occurred with the data manipulator: {str(e)}")
            print("An error has occurred, check error.log")

