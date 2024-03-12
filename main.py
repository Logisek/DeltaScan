from deltascan.main import DeltaScan
from deltascan.core.exceptions import DScanException
from deltascan.cli.data_presentation import (export_port_scans_cli,
                                             export_scans_from_database)
import argparse
import os

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
    parser.add_argument("--n-scans", help="N scan number", required=False)
    parser.add_argument("--date", help="Date of oldest scan to compare", required=False)
    parser.add_argument("-h", "--host", help="select scanning target host", required=False)

    clargs = parser.parse_args()

    # output_file = clargs.output

    # if output_file is None:
    #     print(f"Output file: {output_file}")

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
        dscan = DeltaScan()
        if clargs.action == 'scan':

            result = dscan.port_scan(
                clargs.conf_file,
                clargs.profile,
                clargs.host)

            printable = export_port_scans_cli(result)

        elif clargs.action == 'compare':

            dscan.compare(
                clargs.host,
                clargs.n_scans,
                clargs.date,
                clargs.profile)

        elif clargs.action == 'view':

            result = dscan.view(
                clargs.host,
                clargs.n_scans,
                clargs.date,
                clargs.profile)

            printable = export_scans_from_database(result)

        elif clargs.action == 'report':

            dscan.pdf_report()

        else:
            print("Invalid action")
            os._exit(1)

        print(printable)
    except DScanException as e:
        print(f"An error occurred: {str(e)}")
        os._exit(1)

if __name__ == "__main__":
    run()