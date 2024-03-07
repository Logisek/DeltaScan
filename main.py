from deltascan.main import DeltaScan
import argparse
import os

def run():
    """
    Entry point for the command line interface.
    """
    parser = argparse.ArgumentParser(prog='deltascan', description='A package for scanning deltas', add_help=False)
    parser.add_argument("-a", "--action", help='the command to run', required=True,
                        choices=['scan','view', 'report'])
    parser.add_argument("-o", "--output", help='output file', required=False)
    parser.add_argument("-p", "--profile", help="select scanning profile", required=True)
    parser.add_argument("-c", "--conf-file", help="select profile file to load", required=False)
    parser.add_argument("-h", "--host", help="select scanning target host", required=False)

    clargs = parser.parse_args()

    # output_file = clargs.output

    # if output_file is None:
    #     print(f"Output file: {output_file}")

    if clargs.action == 'scan' and clargs.host is None:
        print("Host not provided")
        os.exit(1)

    dscan = DeltaScan()
    if clargs.action == 'scan':
        dscan.port_scan(
            clargs.conf_file,
            clargs.profile,
            clargs.host)
    elif clargs.action == 'view':
        dscan.view()
    elif clargs.action == 'report':
        dscan.pdf_report()
    else:
        print("Invalid action")

if __name__ == "__main__":
    run()