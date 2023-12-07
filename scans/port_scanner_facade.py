import nmap3
import xml.etree.ElementTree as ET


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
                raise ValueError("xmlToDict function returned None")
                return None

            return scanResults

        except Exception as e:
            logf = open("error.log", "a")
            logf.write("nmap died: " + str(e) + "\n")
            print("An error as occurred, check error.log")
            return None

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
                hostData["address"] = host.find("address").attrib["addr"]
                hostData["status"] = host.find("status").attrib["state"]
                hostData["ports"] = []

                for port in host.find("ports").findall("port"):
                    portData = {}
                    portData["portid"] = port.attrib["portid"]
                    portData["state"] = port.find("state").attrib["state"]
                    hostData["ports"].append(portData)
                scanData.append(hostData)

            return scanData

        except Exception as e:
            logf = open("error.log", "a")
            logf.write("xmlToDict died: " + str(e) + "\n")
            print("An error has occurred, check error.log")
            return None


# Helper method to explore XML structure
def explore_xml(element, indent=0):
    print(" " * indent + element.tag)
    for child in element:
        explore_xml(child, indent + 2)
