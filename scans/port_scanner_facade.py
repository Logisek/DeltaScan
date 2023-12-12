import nmap3
import logging

# import xml.etree.ElementTree as ET


logging.basicConfig(filename="error.log", level=logging.DEBUG)


class PortScannerFacade:
    def __init__(self):
        self.scanner = nmap3.Nmap()
        self.scanner.as_root = True

    def scanCommand(self, target, arg, args=None, timeout=None):
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
            logging.error("nmap died: %s", str(e))
            print("An error as occurred, check error.log")

    def dataManipulator(self, xml):
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
            logging.error("dataManipulator died: %s", str(e))
            print("An error has occurred, check error.log")
