from deltascan.core.utils import find_ports_from_state
from deltascan.cli.utils import bcolors
from deltascan.core.exceptions import DScanResultsSchemaException
from deltascan.core.schemas import (PortScan,
                                    DBPortScan)
from deltascan.core.config import APP_DATE_FORMAT
from marshmallow  import ValidationError
import json
from pprint import pprint
import datetime
# def displayScanList(scanList):
#     """
#     Display the scan list in a tabular format.

#     Args:
#         scanList (list): A list of dictionaries containing scan information.

#     Returns:
#         None
#     """
#     console = Console()
#     table = Table(show_header=True, header_style=headerColor)
#     table.add_column("Scan ID")
#     table.add_column("Profile Name")
#     table.add_column("Scan Arguments")

#     for scan in scanList:
#         table.add_row(str(scan["id"]), scan["profileName"], scan["scanArguments"])

#     console.print(table)


# def displayProfileList(profileList):
#     """
#     Display the profile list in a tabular format.

#     Args:
#         profileList (list): A list of dictionaries containing profile information.

#     Returns:
#         None
#     """
#     console = Console()
#     table = Table(show_header=True, header_style=headerColor)
#     table.add_column("Profile ID")
#     table.add_column("Profile Name")

#     for profile in profileList:
#         table.add_row(str(profile["id"]), profile["profileName"])

#     console.print(table)


# def displayScanResults(results):
#     """
#     Display the scan results in a tabular format.

#     Args:
#         results (list): A list of dictionaries containing scan results for each host.

#     Returns:
#         None
#     """
#     console = Console()
#     table = Table(show_header=True, header_style=headerColor)
#     table.add_column("Host")
#     table.add_column("OS")
#     table.add_column("Ports")
#     table.add_column("Status")

#     for host in results:
#         if host["state"]:
#             state = "up"
#         else:
#             state = "down"

#         ports = cleanPorts(host["ports"])
#         table.add_row(host["host"], host["os"], ports, state)

#     console.print(table)


# def cleanPorts(ports):
#     """
#     Cleans up the port list for display.

#     Args:
#         ports (list): A list of dictionaries containing port information.

#     Returns:
#         cleanPorts (str): A string containing the port information.
#     """
#     cleanPorts = ""
#     for port in ports:
#         cleanPorts = (
#             str(cleanPorts)
#             + str(port.get("portid", "na"))
#             + "/"
#             + str(port.get("service", "na"))
#             + "/"
#             + str(port.get("product", "na"))
#             + "/"
#             + str(port.get("state", "na"))
#             + "\n"
#         )

#     return cleanPorts

def export_port_scans_to_cli(port_scans: list[PortScan], port_state_type: str = "all", action: str = "scan"):
    """
    Export port scans to a formatted string for command-line interface.

    Args:
        port_scans (list): A list of dictionaries representing port scans.

    Returns:
        str: A formatted string containing the port scan information.

    """
    try:
        PortScan(many=True).load(port_scans)
    except ValidationError as err:
        raise DScanResultsSchemaException(str(err))
    output = ""
    for sc in port_scans:

        for key, value in sc.items():
            if key == "ports":
                if  "open" in port_state_type or action == "scan":
                    open_ports = find_ports_from_state(value, "open")
                    output += "open ports:\n"
                    for p in open_ports:
                        output += "  "
                        for opkey, opvalue in p.items():
                            if "port" in opkey:
                                output += f"{bcolors.OKGREEN}{opvalue}{bcolors.ENDC}"
                            else:
                                output += f"/{opvalue}"

                        output += "\n"
                if  "closed" in port_state_type or action == "scan":
                    closed_ports = find_ports_from_state(value, "closed")
                    output += "closed ports:\n"
                    for p in closed_ports:
                        output += "  "
                        for cpkey, cpvalue in p.items():
                            if "port" in cpkey:
                                output += f"{bcolors.FAIL}{cpvalue}{bcolors.ENDC}"
                            else:
                                output += f"/{cpvalue}"
                        output += "\n"
                if "filtered" in port_state_type or action == "scan":
                    closed_ports = find_ports_from_state(value, "filtered")
                    output += "filtered ports:\n"
                    for p in closed_ports:
                        output += "  "
                        for cpkey, cpvalue in p.items():
                            if "port" in cpkey:
                                output += f"{bcolors.FAIL}{cpvalue}{bcolors.ENDC}"
                            else:
                                output += f"/{cpvalue}"
                        output += "\n"
            else:
                if "host" in key:
                    output += f"{bcolors.WARNING}{key}: {value}{bcolors.ENDC}\n"
                else:
                    output += f"{key}: {value}\n"
    return output

def export_scans_from_database_format(port_scans: list[DBPortScan], port_state_type: str = "all", verbose: bool = False, action: str = "scan"):
    """
    Export port scans from the database.

    Args:
        port_scans (list[DBPortScan]): A list of DBPortScan objects representing the port scans.

    Returns:
        str: The exported port scans as a string.

    Raises:
        DScanResultsSchemaException: If there is a validation error with the DBPortScan objects.
    """
    try:
        DBPortScan(many=True).load(port_scans)
    except ValidationError as err:
        raise DScanResultsSchemaException(str(err))
    output = ""
    for sc in port_scans:
        for key, value in sc.items():
            if "host" in key or "id" in key or "result_hash" in key:
                pass
            elif "results" in key:
                output += export_port_scans_to_cli([value], port_state_type, action)
            else:
                if verbose is False and key in ["profile_name", "created_at"]:
                    continue
                output += f"{bcolors.BOLD}{key}: {value}{bcolors.ENDC}\n"
        output += "\n"
    return output

def print_diffs(diffs, last_n):
    """
    Print the differences between two scan results.

    Args:
        diffs (list): A list of dictionaries containing the differences between two scan results.

    Returns:
        None
    """
    # print(json.dumps(diffs, indent=4))
    for idx, diff in enumerate(diffs):
        if idx == int(last_n):
            break
        print(f"{bcolors.BOLD}Scan {bcolors.WARNING}{diff['dates'][0]}  {bcolors.ENDC}{print_is_today(diff['dates'][0])} has the following differences from scan {bcolors.WARNING}{diff['dates'][1]} {print_is_today(diff['dates'][1])}: {bcolors.ENDC}")
        for k, v in diff["diffs"]["changed"].items():
            for sk,sv in v["changed"].items():
                for vk,vv in sv["changed"].items():
                    print(f"{bcolors.OKCYAN}{k}:{bcolors.ENDC} {bcolors.OKBLUE}{sk}{bcolors.ENDC} -> {bcolors.UNDERLINE}{vk}{bcolors.ENDC} changed from ", print_port_state_type(vv["from"]), " to ", print_port_state_type(vv["to"]))
        print("\n")

def print_port_state_type(port_state_type):
    """
    Print the port state type.

    Args:
        port_state_type (str): The port state type to be printed.

    Returns:
        None
    """
    if port_state_type == "open":
        return f"{bcolors.OKGREEN}{port_state_type}{bcolors.ENDC}"
    elif port_state_type == "closed":
        return f"{bcolors.FAIL}{port_state_type}{bcolors.ENDC}"
    elif port_state_type == "filtered":
        return f"{bcolors.FAIL}{port_state_type}{bcolors.ENDC}"
    else:
        return f"_"
    
def print_is_today(date):
    """
    Print if the date is today.

    Args:
        date (datetime): The date to be checked.

    Returns:
        None
    """
    if datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date():
        return f"({bcolors.OKGREEN}Today{bcolors.ENDC})"
    elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=1):
        return f"({bcolors.OKGREEN}Yesterday{bcolors.ENDC})"
    elif datetime.datetime.strptime(date,APP_DATE_FORMAT).date() == datetime.datetime.now().date() - datetime.timedelta(days=2):
        return f"({bcolors.OKGREEN}Day before yesterday{bcolors.ENDC})"
    else:
        return ""