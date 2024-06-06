from deltascan.core.deltascan import DeltaScan
from deltascan.core.exceptions import (DScanException, ExitInteractiveShell)
from deltascan.core.config import (BANNER, VERSION_STR)
from deltascan.core.utils import ThreadWithException
from deltascan.cli.cli_output import (CliOutput)
import argparse
import os
import cmd
from rich.live import Live
import pkg_resources
import signal
import select
import sys
from time import sleep


def clear_screen():
    # The -x flag clears only visible part of the screen and lets us scroll up
    os.system("clear -x")


def interactive_shell(_app, _ui, _interactive):
    """
    Starts an interactive shell for the application.

    Args:
        _app (object): The application object.
        ui (dict): A dictionary containing UI related objects.

    Returns:
        None
    """
    shell = Shell(_app)
    __only_first_time = True

    while _app.cleaning_up is False:
        if _app.is_running is True and _interactive is True and __only_first_time is True:
            __only_first_time = False
            pass
        else:
            # Setting input with timeout in order not to block in case of cancel
            # and _app.cleaning_up is re-checked
            a, b, c = select.select([sys.stdin], [], [], 2)
            if a == [] and b == [] and c == []:
                continue
            else:
                # the line below is necessary since we are clearing the stdin buffer
                # if we ommit this line, the stdin buffer is not getting cleared
                sys.stdin.readline().strip()
        try:
            _ui["ui_live"].stop()
            clear_screen()
            # sys.stdout.write('\x1b[1A')
            # # delete last line
            # sys.stdout.write('\x1b[2K')
            _app.is_interactive = True
            shell.cmdloop()
        except (KeyboardInterrupt, ExitInteractiveShell):
            pass
        # TODO: need to find a way to print the scan progress bars more nicelly
        _app.is_interactive = False
        _ui["ui_live"].start()


class Shell(cmd.Cmd):
    intro = ''

    prompt = '\033[92mdeltascan>:\033[0m'

    def __init__(self, _app):
        """
        Initialize the Cmd class.

        Args:
            _app: The application object.

        """
        super().__init__()
        self._app = _app
        self.last_index_to_uuid_mapping = None

    def do_conf(self, v):
        """conf [key=value]
        Modify configuration values real-time.
        Ex. conf output_file=/tmp/output.json"""
        try:
            if len(v.split("=")) <= 1:
                conf_key = v.split("=")[0]
                if conf_key == "output_file" or conf_key == "":
                    print(f"{'output_file: ' + '':<20} {self._app.output_file}")
                if conf_key == "template_file" or conf_key == "":
                    print(f"{'template_file: ' + '':<20} {self._app.template_file}")
                if conf_key == "import_file" or conf_key == "":
                    print(f"{'import_file: ' + '':<20} {self._app.import_file}")
                if conf_key == "diff_files" or conf_key == "":
                    print(f"{'diff_files: ' + '':<20} {self._app.diff_files}")
                if conf_key == "n_scans" or conf_key == "":
                    print(f"{'n_scans: ' + '':<20} {self._app.n_scans}")
                if conf_key == "n_diffs" or conf_key == "":
                    print(f"{'n_diffs: ' + '':<20} {self._app.n_diffs}")
                if conf_key == "fdate" or conf_key == "":
                    print(f"{'From date [fdate]: ' + '':<20} {self._app.fdate}")
                if conf_key == "tdate" or conf_key == "":
                    print(f"{'To date [tdate]: ' + '':<20} {self._app.tdate}")
                if conf_key == "suppress" or conf_key == "":
                    print(f"{'suppress: ' + '':<20} {self._app.suppress}")
                if conf_key == "host" or conf_key == "":
                    print(f"{'host: ' + '':<20} {self._app.host}")
                if conf_key == "profile" or conf_key == "":
                    print(f"{'profile: ' + '':<20} {self._app.profile}")
                return

            conf_key = v.split("=")[0]
            conf_value = v.split("=")[1]

            def __norm_value(v):
                return None if v == "" or v == "None" else v

            if conf_key == "output_file":
                self._app.output_file = __norm_value(conf_value)
            elif conf_key == "template_file":
                self._app.template_file = __norm_value(conf_value)
            elif conf_key == "import_file":
                self._app.import_file = __norm_value(conf_value)
            elif conf_key == "n_scans":
                self._app.n_scans = __norm_value(conf_value)
            elif conf_key == "n_diffs":
                self._app.n_diffs = __norm_value(conf_value)
            elif conf_key == "fdate":
                self._app.fdate = __norm_value(conf_value)
            elif conf_key == "tdate":
                self._app.tdate = __norm_value(conf_value)
            elif conf_key == "suppress":
                self._app.suppress = False if __norm_value(conf_value).lower() == "false" else True
            elif conf_key == "host":
                self._app.host = __norm_value(conf_value)
            elif conf_key == "profile":
                self._app.profile = __norm_value(conf_value)
            else:
                print("Invalid configuration value")
        except Exception as e:
            print(str(e))

    def do_scan(self, v):
        """scan
        Add ad-hoc scans: scan 10.10.10.10 PROFILE_NAME"""
        try:
            if len(v.split(" ")) != 2:
                print("Invalid input. Provide a host and a profile: scan <host> <profile>")
                return
            v1, v2 = v.split(" ")
            _r = self._app.add_scan(v1, v2)
            if _r is False:
                print("Not starting scan. Check your host and profile. Maybe the scan is already in the queue.")
        except Exception as e:
            print(str(e))

    def do_view(self, _):
        """view
        Execute the view action using the current configuration"""
        try:
            _r = self._app.view()
            output = CliOutput(_r, self._app.suppress)
            _res = output.display()
            self.last_index_to_uuid_mapping = _res
        except Exception as e:
            print(str(e))

    def do_diff_files(self, v):
        """diff_files
        Execute the difference comparison using the current configuration.
        Ex. diff_files file1.xml,file2.xml,file3.xml"""
        try:
            _r = self._app.files_diff(None if v == "" else v)
            output = CliOutput(_r)
            output.display()
        except Exception as e:
            print(str(e))

    def do_diff(self, v):
        """diff
        Execute the differece comparison using the current configuration.
        Ex. diff
        You can also provide a list of indexes from the last view results.
        Ex. diff 1,2,3,4,5
        """
        try:
            if len(v.split(",")) > 1 and \
                    self.last_index_to_uuid_mapping is not None:
                _idxs = v.split(",")
                _uuids = []
                for _key in self.last_index_to_uuid_mapping:
                    if _key in _idxs:
                        _uuids.append(self.last_index_to_uuid_mapping[_key])
                if len(_uuids) < 2:
                    print("Provide 2 valid indexes from the view list."
                          " Re-run view to view the last results.")
                r = self._app.diffs(uuids=_uuids)
            else:
                r = self._app.diffs()

            output = CliOutput(r)
            output.display()
        except Exception as e:
            print(str(e))

    def do_report(self, _):
        """report
        Generate a report using the current configuration. Ex. report"""
        try:
            _ = self._app.report_result()
            print("File configured", self._app.output_file)
        except Exception as e:
            print(str(e))

    def do_imp(self, v):
        """imp
        Import a file using the current configuration. Ex. imp"""
        # Getting the requested scans from the list of the last scans
        try:
            if v == "":
                v = None

            r = self._app.import_data(v)
            output = CliOutput(r)
            output.display()
        except Exception as e:
            print(str(e))

    def do_profiles(self, _):
        """profiles
        List all available profiles"""
        try:
            r = self._app.list_profiles()
            CliOutput.profiles(r)
        except Exception as e:
            print(str(e))

    def do_clear(self, _):
        """clear
        Clear console"""
        clear_screen()

    def do_q(self, _):
        """q or quit
        Quit interactive shell"""
        if self._app.scans_to_wait == 0 and self._app.scans_to_execute == 0:
            print("All scans have been executed...")
        clear_screen()
        return True

    def do_quit(self, _):
        """q or quit
        Quit interactive shell"""
        if self._app.scans_to_wait == 0 and self._app.scans_to_execute == 0:
            print("All scans have been executed...")
        clear_screen()
        return True

    def do_exit(self, _):
        """exit
        Exit Deltascan"""
        try:
            print("\nShutting down...")
            self._app.cleanup()
            while self._app.cleaning_up is False or self._app.is_running is True:
                sleep(1)
                continue
            print("Cancelled all scans. Exiting with grace ...")
            os._exit(0)
        except Exception as e:
            print(str(e))
            os._exit(1)


def signal_handler(signal, frame):
    print("Exiting without cleanup :-(")
    os._exit(1)


def run():
    """
    Entry point for the command line interface.
    """
    parser = argparse.ArgumentParser(
        prog='deltascan', description='A package for scanning deltas')
    parser.add_argument(
        "action", help='the command to run', choices=['scan', 'diff', 'view', 'import', 'version'])
    parser.add_argument("-o", "--output", help='output file', required=False)
    parser.add_argument("-d", "--diff-files",
                        help='comma separated files to find their differences (xml)',
                        required=False)
    parser.add_argument(
        "--single", default=False, action='store_true',
        help='if flag exists, it exports scans as single entries', required=False)
    parser.add_argument(
        "--template", help='the html template file to generate .html and .pdf reports',
        required=False)
    parser.add_argument(
        "-i", "--import", dest="import_file",
        help='import file (csv, xml). Csv must be generated by deltascan and XML must be generated by nmap',
        required=False)
    parser.add_argument(
        "-p", "--profile", help="select scanning profile that exists in config file or already in database",
        required=False)
    parser.add_argument(
        "-c", "--conf-file",
        help="path to configuration file", required=False)
    # parser.add_argument(
    #     "-v", "--verbose", default=False, action='store_true',
    #     help="verbose output", required=False)
    parser.add_argument(
        "-s", "--suppress", default=False, action='store_true',
        help="suppress output", required=False)
    parser.add_argument(
        "--n-scans", help="limit of scans databse queries. It is applied in scans view as well as scans diff",
        required=False)
    parser.add_argument(
        "--n-diffs", default=1,
        help="limit of the diff results", required=False)
    parser.add_argument(
        "--from-date", help="date of oldest scan to compare", required=False)
    parser.add_argument(
        "--to-date", help="date of newest scan to compare", required=False)
    parser.add_argument(
        "--port-type", default="open,closed,filtered",
        help="Type of port status (open,filter,closed,all)", required=False)
    parser.add_argument(
        "-t", "--target", dest="host",
        help="select target host/subnet to scan", required=False)
    parser.add_argument(
        "-it", "--interactive", default=False, action='store_true',
        help="execute action and go in interactive mode", required=False)
    parser.add_argument(
        "-db", "--db-path", default="", dest="db_path",
        help="set the sqlite database path", required=False)

    clargs = parser.parse_args()

    output_file = clargs.output

    if clargs.action == 'scan' and (clargs.host is None or
                                    clargs.profile is None or
                                    clargs.conf_file is None):
        print("Host, profile or configuration file not provided")
        os._exit(1)

    if (clargs.action != "view" or clargs.action != "import") \
            and clargs.n_scans is None:
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

    config = {
        "is_interactive": clargs.interactive,
        "output_file": output_file,
        "single": clargs.single,
        "template_file": clargs.template,
        "import_file": clargs.import_file,
        "diff_files": clargs.diff_files,
        "action": clargs.action,
        "profile": clargs.profile,
        "conf_file": clargs.conf_file,
        "verbose": None,
        "suppress": clargs.suppress,
        "n_scans": clargs.n_scans,
        "n_diffs": clargs.n_diffs,
        "fdate": clargs.from_date,
        "tdate": clargs.to_date,
        "port_type": clargs.port_type,
        "host": clargs.host,
        "db_path": clargs.db_path
    }

    ui_context = {
        "progress": 0
    }

    result = []
    lv = Live(None, refresh_per_second=5)

    ui_context["ui_live"] = lv
    ui_context["ui_instances"] = {}
    ui_context["show_nmap_logs"] = False

    _dscan = DeltaScan(config, ui_context, result)

    try:
        _version = pkg_resources.require("deltascan")[0].version
        if clargs.action == "version":
            print(VERSION_STR.format(_version))
            os._exit(0)

        if clargs.interactive is False:
            print(BANNER.format(
                _version,
                _dscan.stored_scans_count(),
                _dscan.stored_profiles_count(),
                clargs.profile,
                clargs.conf_file,
                output_file,
                clargs.db_path))

        if clargs.action == 'scan':
            _dscan_thread = ThreadWithException(target=_dscan.scan)
            _dscan.add_scan(config["host"], config["profile"])
            ui_context["ui_live"].start()
            _shell_thread = ThreadWithException(
                target=interactive_shell, args=(_dscan, ui_context, clargs.interactive,))

            _dscan_thread.start()
            _shell_thread.start()
            _dscan_thread.join()

            if clargs.interactive or _dscan.is_interactive:
                _dscan.is_interactive = True
            else:
                print("No scans left in the queue... Exiting.")
                output = CliOutput([
                    item for sublist in [
                        _s["scans"] for _s in _dscan.result if "scans" in _s
                        ] for item in sublist
                    ], _dscan.suppress)

                output.display()
                os._exit(0)

        elif clargs.action == 'diff':
            if clargs.diff_files is not None:
                _r = _dscan.files_diff()
            else:
                _r = _dscan.diffs()
            output = CliOutput(_r)
            output.display()
        elif clargs.action == 'view':
            _r = _dscan.view()
            output = CliOutput(_r)
            output.display()
        elif clargs.action == 'import':
            _r = _dscan.import_data()
            output = CliOutput(_r)
            output.display()
        else:
            if clargs.interactive is True:
                print("No action provided. Starting interactive shell.")
            else:
                print("Invalid action. Exiting...")

    except DScanException as e:
        print(f"Error occurred: {str(e)}")
        os._exit(1)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal_handler)
        print("\nCancelling running scans and closing ...")
        _dscan.cleanup()
        while _dscan.cleaning_up is False or _dscan.is_running is True:
            sleep(1)
            continue
        print("Cancelled all scans. Exiting with grace ...")
        os._exit(0)
    except Exception as e:
        print(f"Unknown error occurred: {str(e)}")
        os._exit(1)


if __name__ == "__main__":
    run()
