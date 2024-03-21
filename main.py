from deltascan.main import DeltaScan
from deltascan.core.exceptions import DScanException
from deltascan.cli.data_presentation import (export_port_scans_to_cli,
                                             export_scans_from_database_format,
                                             print_diffs)
import argparse
import os
import json
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

    if output_file is None:
        print(f"Output file: {output_file}")

    if clargs.action == 'scan' and (clargs.host is None or
                                    clargs.profile is None or
                                    clargs.conf_file is None):
        print("Host not provided")
        os.exit(1)
    
    if clargs.action == 'compare' and (
        clargs.host is None or 
        clargs.n_scans is None or 
        clargs.date is None or
        clargs.profile is None):
        
        print("No scan count, host, profile or date provided for comparison")
        os._exit(1)

    result = ""
    printable = ""
    try:
        # TODO: think about using @dataclass for structuring the configuration
        dscan = DeltaScan({
            "output_file": output_file
        })
        if clargs.action == 'scan':

            result = dscan.port_scan(
                clargs.conf_file,
                clargs.profile,
                clargs.host)

            printable = export_port_scans_to_cli(result)
            print(printable)

        elif clargs.action == 'compare':

            diffs = dscan.compare(
                clargs.host,
                clargs.n_scans,
                clargs.date,
                clargs.profile)

            print_diffs(diffs, clargs.n_diffs)

        elif clargs.action == 'view':

            result = dscan.view(
                clargs.host,
                clargs.n_scans,
                clargs.date,
                clargs.profile,
                clargs.port_type)

            printable = export_scans_from_database_format(result, clargs.port_type, clargs.verbose, clargs.action)
            print(printable)

        elif clargs.action == 'report':
            dscan.report(
                clargs.host,
                clargs.n_scans,
                clargs.date,
                clargs.profile,
                clargs.port_type)

        else:
            print("Invalid action")
            os._exit(1)

        
    except DScanException as e:
        print(f"An error occurred: {str(e)}")
        os._exit(1)

if __name__ == "__main__":
    run()