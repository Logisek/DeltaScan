import nmap3
import logging

# import xml.etree.ElementTree as ET


logging.basicConfig(
    level=logging.INFO,
    filename="error.log",
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class PortScannerFacade:
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

    def __init__(self):
        self.scanner = nmap3.Nmap()
        self.scanner.as_root = True

    def scanCommand(self, target, arg, args=None, timeout=None):
        """
        Performs the port scan command and returns the scan results.

        Args:
            target (str): The target IP address or hostname.
            arg (str): The nmap scan command argument.
            args (str, optional): Additional arguments to be passed to the nmap scan command. Defaults to None.
            timeout (int, optional): The timeout value for the scan command. Defaults to None.

        Returns:
            list: A list of dictionaries representing the scan data.

        Raises:
            ValueError: If the dataManipulator function returns None.
        """
        self.target = target
        self.args = arg
        self.timeout = timeout

        try:
            scanResults = self.scanner.scan_command(self.target, self.args)
            scanResults = self.dataManipulator(scanResults)

            if scanResults is None:
                raise ValueError("dataManipulator function returned None")

            return scanResults

        except Exception as e:
            logging.error("An error ocurred with nmap:", str(e))

    def dataManipulator(self, xml):
        """
        Manipulates the XML scan results and returns a list of dictionaries representing the scan data.

        Args:
            xml (str): The XML scan results.

        Returns:
            list: A list of dictionaries representing the scan data.
        """
        try:
            scanData = []

            for runstat in xml.findall("runstats"):
                runData = {}
                runData["hostsUp"] = runstat.find("hosts").attrib.get("up")
                runData["hostsDown"] = runstat.find("hosts").attrib.get("down")
                runData["totalHosts"] = runstat.find("hosts").attrib.get("total")
                runData["elapsed"] = runstat.find("finished").attrib.get("elapsed")
                runData["exit"] = runstat.find("finished").attrib.get("exit")
                runData["time"] = runstat.find("finished").attrib.get("time")
                scanData.append(runData)

            for host in xml.findall("host"):
                hostData = {}
                if host.findall("address"):
                    hostData["address"] = host.find("address").attrib["addr"]
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

                scanData.append(hostData)

            return scanData

        except Exception as e:
            logging.error("An error occurred with the data manipulator", str(e))
            print("An error has occurred, check error.log")
