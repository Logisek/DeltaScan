from deltascan.core.deltascan import DeltaScan
from deltascan.core.exceptions import DScanException
from deltascan.cli.data_presentation import (CliOutput)
import argparse
import os

from rich.console import Console
from rich.live import Live
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.text import Text
from rich.columns import Columns

import time

def run():
    """
    Entry point for the command line interface.
    """
    parser = argparse.ArgumentParser(prog='deltascan', description='A package for scanning deltas')
    parser.add_argument("-a", "--action", help='the command to run', required=True,
                        choices=['scan', 'compare', 'view', 'import'])
    parser.add_argument("-o", "--output", help='output file', required=False)
    parser.add_argument("--single", default=False, action='store_true', help='export scans as single entries', required=False)
    parser.add_argument("--template", help='template file', required=False)
    parser.add_argument("-i", "--import", dest="import_file", help='import file', required=False)
    parser.add_argument("-p", "--profile", help="select scanning profile", required=False)
    parser.add_argument("-c", "--conf-file", help="select profile file to load", required=False)
    parser.add_argument("-v", "--verbose", default=False, action='store_true', help="verbose output", required=False)
    parser.add_argument("--n-scans", help="N scan number", required=False)
    parser.add_argument("--n-diffs", default=1, help="N scan differences", required=False)
    parser.add_argument("--from-date", help="Date of oldest scan to compare", required=False)
    parser.add_argument("--to-date", help="Created at date, of the queried scan", required=False)
    parser.add_argument("--port-type", default="open,closed,filtered", help="Type of port status open,filter,closed,all", required=False)
    parser.add_argument("-t", "--target", dest="host", help="select scanning target host", required=False)

    clargs = parser.parse_args()

    output_file = clargs.output

    if clargs.action == 'scan' and (clargs.host is None or
                                    clargs.profile is None or
                                    clargs.conf_file is None):
        print("Host, profile or configuration file not provided")
        os._exit(1)
    
    if (clargs.action != "view" or clargs.action != "import") and clargs.n_scans is None:
        clargs.n_scans = 10 
    
    if clargs.action == 'compare' and (
        clargs.host is None or 
        clargs.n_scans is None or 
        clargs.from_date is None or
        clargs.profile is None):
        
        print("No scan count, host, profile or dates provided for comparison")
        os._exit(1)

    if clargs.action == "import" and clargs.import_file is None:
        print("No import file provided")
        os._exit(1)

    ui_context = {
        "progress": 0
    }

    config = {
        "output_file": output_file,
        "single": clargs.single,
        "template_file": clargs.template,
        "import_file": clargs.import_file,
        "action": clargs.action,
        "profile": clargs.profile,
        "conf_file": clargs.conf_file,
        "verbose": clargs.verbose,
        "n_scans": clargs.n_scans,
        "n_diffs": clargs.n_diffs,
        "fdate": clargs.from_date,
        "tdate": clargs.to_date,
        "port_type": clargs.port_type,
        "host": clargs.host,
    }

    progress_bar = Progress(
        TextColumn("[bold light_slate_gray]Scanning ...", justify="right"),
        BarColumn(bar_width=60, complete_style="green"),
        TextColumn("[progress.percentage][light_slate_gray]{task.percentage:>3.1f}%"))

    _prog = progress_bar.add_task("", total=100)
    progress_bar.update(_prog, advance=1)

    text = Text(no_wrap=True, overflow="fold", style="dim light_slate_gray")
    text.stylize("bold magenta", 0, 6)

    lv = Live(Columns([progress_bar, text], width=100), refresh_per_second=5)

    ui_context["ui_live"] = lv
    ui_context["ui_instances"] = {"progress_bar": progress_bar, "text": text}
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
        elif clargs.action == 'import':
            result = dscan.import_data()
            output = CliOutput(result)
            output.display()
        else:
            print("Invalid action")
            os._exit(1)

    except DScanException as e:
        print(f"Error occurred: {str(e)}")
        os._exit(1)

if __name__ == "__main__":
    print(os.getcwd())
    run()