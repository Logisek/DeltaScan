from deltascan.main import DeltaScan
from deltascan.core.exceptions import DScanException
from deltascan.cli.data_presentation import (CliOutput)
import argparse
import os

from rich.console import Console

from rich.progress import Progress
import time

def run():
    """
    Entry point for the command line interface.
    """
    parser = argparse.ArgumentParser(prog='deltascan', description='A package for scanning deltas', add_help=False)
    parser.add_argument("-a", "--action", help='the command to run', required=True,
                        choices=['scan', 'compare', 'view', 'report'])
    parser.add_argument("-o", "--output", help='output file', required=False)
    parser.add_argument("-p", "--profile", help="select scanning profile", required=False)
    parser.add_argument("-c", "--conf-file", help="select profile file to load", required=False)
    parser.add_argument("-v", "--verbose", default=False, action='store_true', help="verbose output", required=False)
    parser.add_argument("--n-scans", default=10, help="N scan number", required=False)
    parser.add_argument("--n-diffs", default=1, help="N scan differences", required=False)
    parser.add_argument("--date", help="Date of oldest scan to compare", required=False)
    parser.add_argument("--port-type", default="open,closed,filtered", help="Type of port status open,filter,closed,all", required=False)
    parser.add_argument("-h", "--host", help="select scanning target host", required=False)

    clargs = parser.parse_args()

    output_file = clargs.output

    if clargs.action == 'scan' and (clargs.host is None or
                                    clargs.profile is None or
                                    clargs.conf_file is None):
        print("Host, profile or configuration file not provided")
        os._exit(1)
    
    if clargs.action == 'compare' and (
        clargs.host is None or 
        clargs.n_scans is None or 
        clargs.date is None or
        clargs.profile is None):
        
        print("No scan count, host, profile or date provided for comparison")
        os._exit(1)

    ui_context = {
        "progress": 0
    }

    config = {
        "output_file": output_file,
        "action": clargs.action,
        "profile": clargs.profile,
        "conf_file": clargs.conf_file,
        "verbose": clargs.verbose,
        "n_scans": clargs.n_scans,
        "n_diffs": clargs.n_diffs,
        "date": clargs.date,
        "port_type": clargs.port_type,
        "host": clargs.host,
    }

    progress_bar = Progress()
    _prog = progress_bar.add_task("[cyan]Scanning...", total=100)
    progress_bar.update(_prog, advance=1)
    ui_context["ui_instances"] = {"progress_bar": progress_bar}
    ui_context["ui_instances_ids"] = {"progress_bar": _prog}
    ui_context["ui_instances_callbacks"] = {"progress_bar_update": progress_bar.update, "progress_bar_start": progress_bar.start_task}
    ui_context["ui_instances_callbacks_args"] = {"progress_bar": {"args": [], "kwargs": {"completed": 0}}}

    try:
        # TODO: raise exception on configuration false schema
        dscan = DeltaScan(config, ui_context)
        if clargs.action == 'scan':
            result = dscan.port_scan()
            output = CliOutput(result)
            output.display()
        elif clargs.action == 'compare':
            diffs = dscan.compare()
            output = CliOutput(diffs)
            output.display()
        elif clargs.action == 'view':
            result = dscan.view()
            output = CliOutput(result)
            output.display()
        else:
            print("Invalid action")
            os._exit(1)

    except DScanException as e:
        print(f"An error occurred: {str(e)}")
        os._exit(1)

if __name__ == "__main__":
    run()