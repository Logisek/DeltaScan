import re
import os


class NmapParser:
    def __init__(self, filepaths):
        self.filepaths = filepaths.split(",")
        self.scans = []

    def get_scans(self):
        return self.scans

    def parse(self):
        for filepath in self.filepaths:
            scan = {"file": os.path.basename(filepath), "hosts": []}
            with open(filepath, "r") as file:
                for line in file:
                    if line.startswith("Host") and "Ports" in line:
                        scan["hosts"].append(self.parse_data(line))
                    elif line.startswith("# Nmap"):
                        self.parse_scan_info(line)
            self.scans.append(scan)

    def parse_data(self, line):
        host_ip = self.parse_host_ip(line)
        host_status = False
        host_ports = tuple()

        # if "Status" in line:
        #     match_host_status = re.search(r"Status: (\w+)", line)
        #     if match_host_status:
        #         status = match_host_status.group(1)
        #         if status == "Up":
        #             host_status = True
        #         else:
        #             host_status = False

        if "Ports" in line:
            host_status = True  # TODO: Fact check if ports = host up
            host_ports = re.findall(r"(\d+)/(\w+)/(\w+)//(.*?)(?:/,|$)", line)

            return {
                "host": host_ip,
                "status": host_status,
                "ports": host_ports,
            }

        else:
            return False

    def parse_ports(self, ports):
        for port in ports:
            port_number, state, protocol, service = port
            product = service.split("//")[1] if "//" in service else "Not Available"
            service = service.split("//")[0]
            print(
                f"Port: {port_number}, State: {state}, Protocol: {protocol}, Service: {service}, Product: {product}"
            )

    def parse_host_ip(self, line):
        match_host_ip = re.search(r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        host_ip = ""
        if match_host_ip:
            host_ip = match_host_ip.group(1)
        return host_ip

    def parse_scan_info(self, line):
        # TODO: Extract scan info
        pass


# For debugging purposes
# if __name__ == "__main__":
#     filepaths = "grep_multi_1.log,grep_multi_2.log"
#     parser = NmapParser(filepaths)
#     parser.parse()
