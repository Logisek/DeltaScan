import nmap3
import logging

# import xml.etree.ElementTree as ET


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

        scan_results = self._scan(target, scan_args)

        return scan_results


    def _scan(self, target, scan_args):
        """
        Performs the port scan command and returns the scan results.

        Args:
            target (str): The target IP address or hostname.
            scan_args (str): The nmap scan command argument.
        Returns:
            list: A list of dictionaries representing the scan data.

        Raises:
            ValueError: If the dataManipulator function returns None.
        """
        self.target = target
        self.scan_args = scan_args

        try:
            scan_results = self._normalize_port_scan_results(
               self.nmap_scanner.scan_command(target, scan_args) 
            )

            if scan_results is None:
                raise ValueError("dataManipulator function returned None")

            return scan_results

        except Exception as e:
            logging.error("An error ocurred with nmap:", str(e))

    def _normalize_port_scan_results(self, raw_scan_results_xml):
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
                hostData = {}
                if host.findall("address"):
                    hostData["host"] = host.find("address").attrib["addr"]
                if host.findall("status"):
                    hostData["status"] = host.find("status").attrib["state"]
                hostData["ports"] = []

                if host.find("ports"):
                    for port in host.find("ports").findall("port"):
                        portData = {}
                        portData["portid"] = port.attrib["portid"]
                        if port.findall("state"):
                            portData["state"] = port.find("state").attrib["state"]
                        if port.findall("service"):
                            portData["service"] = port.find("service").attrib["name"]
                            portData["serviceProduct"] = port.find(
                                "service"
                            ).attrib.get("product", "unknown")
                        hostData["ports"].append(portData)
                

                # TODO: Needs tweaking to work with multiple osmatches
                if host.find("os"):
                    # ET.dump(host.find("os"))
                    for os in host.find("os").findall("osmatch"):
                        hostData["os"] = os.attrib["name"]

                scan_results.append(hostData)
            return scan_results

        except Exception as e:
            logging.error("An error occurred with the data manipulator", str(e))
            print("An error has occurred, check error.log")

