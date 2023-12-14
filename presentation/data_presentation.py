from rich.console import Console
from rich.table import Table

headerColor = "bold magenta"


def displayScanList(scanList):
    """
    Display the scan list in a tabular format.

    Args:
        scanList (list): A list of dictionaries containing scan information.

    Returns:
        None
    """
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Scan ID")
    table.add_column("Profile Name")
    table.add_column("Scan Arguments")

    for scan in scanList:
        table.add_row(str(scan["id"]), scan["profileName"], scan["scanArguments"])

    console.print(table)


def displayProfileList(profileList):
    """
    Display the profile list in a tabular format.

    Args:
        profileList (list): A list of dictionaries containing profile information.

    Returns:
        None
    """
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Profile ID")
    table.add_column("Profile Name")

    for profile in profileList:
        table.add_row(str(profile["id"]), profile["profileName"])

    console.print(table)


def displayScanResults(results):
    """
    Display the scan results in a tabular format.

    Args:
        results (list): A list of dictionaries containing scan results for each host.

    Returns:
        None
    """
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Host")
    table.add_column("OS")
    table.add_column("Ports")
    table.add_column("Status")

    for host in results:
        if host["state"]:
            state = "up"
        else:
            state = "down"

        ports = cleanPorts(host["ports"])
        table.add_row(host["host"], host["os"], ports, state)

    console.print(table)


def cleanPorts(ports):
    """
    Cleans up the port list for display.

    Args:
        ports (list): A list of dictionaries containing port information.

    Returns:
        cleanPorts (str): A string containing the port information.
    """
    cleanPorts = ""
    for port in ports:
        cleanPorts = (
            str(cleanPorts)
            + str(port.get("port", "na"))
            + "/"
            + str(port.get("service", "na"))
            + "/"
            + str(port.get("product", "na"))
            + "/"
            + str(port.get("state", "na"))
            + "\n"
        )

    return cleanPorts
