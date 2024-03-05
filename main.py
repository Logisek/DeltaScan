from deltascan.main import DeltaScan
import argparse
import os

def run():
    """
    Entry point for the command line interface.
    """
    parser = argparse.ArgumentParser(prog='deltascan', description='A package for scanning deltas', add_help=False)
    parser.add_argument("-c", "--command", help='the command to run', required=True,
                        choices=['scan', 'view', 'report'])
    parser.add_argument("-o", "--output", help='output file', required=False)
    parser.add_argument("-p", "--profile", help="select scanning profile", required=False)
    parser.add_argument("-h", "--host", help="select scanning target host", required=False)
    parser.add_argument("--scan-args", default="", help="extra scannig arguments", required=False)

    clargs = parser.parse_args()

    output_file = clargs.output
    profile = clargs.profile

    if output_file is None:
        print(f"Output file: {output_file}")

    if profile is None:
        profile = "DEFAULT"

    dscan = DeltaScan()
    if clargs.command == 'scan':
        if clargs.host is None:
            print("Host not provided")
            os.exit(1)
        dscan.port_scan(profile, clargs.scan_args)
    elif clargs.command == 'view':
        dscan.view()
    elif clargs.command == 'report':
        dscan.pdf_report()
    else:
        print("Invalid command")

if __name__ == "__main__":
    run()