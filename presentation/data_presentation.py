from rich.console import Console
from rich.table import Table

headerColor = "bold magenta"


def displayScanList(scanList):
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Scan ID")
    table.add_column("Profile Name")
    table.add_column("Scan Arguments")

    for scan in scanList:
        table.add_row(str(scan["id"]), scan["profileName"], scan["scanArguments"])

    console.print(table)


def displayProfileList(profileList):
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Profile ID")
    table.add_column("Profile Name")

    for profile in profileList:
        table.add_row(str(profile["id"]), profile["profileName"])

    console.print(table)


def displayScanResults(results):
    console = Console()
    table = Table(show_header=True, header_style=headerColor)
    table.add_column("Host")
    table.add_column("OS")
    table.add_column("Ports")
    table.add_column("Status")

    # TODO: Display ports. Hosts show up 3 times. Hosts down do not show up at all.
    for host in results:
        # table.add_row(host["host"], host["os"], host["ports"], host["state"])
        if host["state"]:
            state = "up"
        else:
            state = "down"

        table.add_row(host["host"], host["os"], "ports", state)

    console.print(table)
