from libnmap.process import NmapProcess
from libnmap.diff import NmapDiff

from libnmap.parser import NmapParser, NmapParserException
from queue import Queue 
from threading import Thread
import os
from deltascan.core.utils import n_hosts_on_subnet
from time import sleep
import subprocess
from enum import Enum
from contextlib import nullcontext
from deltascan.core.utils import n_hosts_on_subnet


class QueueMsg(Enum):
    DATA = "data"
    PROGRESS = "progress"
    EXIT = "exit"

QMESSAGE_TYPE = "type"
QMESSAGE_HOST = "host"
QMESSAGE_MSG = "msg"

class LibNmapWrapper:
    target: str
    scan_args: str

    def __init__(self, target: str, scan_args: str, ui_context=None):
            """
            Initializes a new instance of the Nmap class.

            Args:
                target (str): The target to scan.
                scan_args (str): The arguments to pass to the Nmap scanner.
                ui_context (optional): The UI context for the scan.

            """
            self.target = target
            self.scan_args = scan_args
            self.ui_context = ui_context

    @classmethod
    def scan(cls, target: str, scan_args: str, ui_context=None):
            """
            Perform a scan on the specified target using the given scan arguments.

            Args:
                target (str): The target to scan.
                scan_args (str): The arguments to pass to the scan.
                ui_context (optional): The UI context for the scan.

            Returns:
                The result of the scan.
            """
            try:
                instance = cls(target, scan_args, ui_context)
                return instance._scan()
            except Exception as e:
                print(f"An error occurred: {str(e)}")
                raise e
    
    def _scan(self):
        """
        Perform a scan using Nmap.

        This method starts a new thread to run the scan and waits for the scan to complete.
        It returns the scan results once all hosts on the subnet have been scanned.

        Returns:
            dict: The scan results.

        """
        _q = Queue()
        _t = Thread(target=self._run, args=(_q,))
        _t.start()
        _d = []
        _scan_finished = False

        with self.ui_context["ui_instances"]["progress_bar"] if self.ui_context is not None else nullcontext() as gs:
            _current_progress = 0
            while True:
                _incoming_msg = _q.get()
                
                if _incoming_msg[QMESSAGE_TYPE] == QueueMsg.DATA:
                    _d = _incoming_msg[QMESSAGE_MSG]
                elif _incoming_msg[QMESSAGE_TYPE] == QueueMsg.EXIT:
                    _scan_finished = True
                elif _incoming_msg[QMESSAGE_TYPE] == QueueMsg.PROGRESS:
                    if self.ui_context is not None:
                        self.ui_context[
                            "ui_instances_callbacks"][
                                "progress_bar_update"](
                                    self.ui_context[
                                        "ui_instances_ids"][
                                            "progress_bar"],
                                    completed=_incoming_msg[QMESSAGE_MSG],
                                    )
                    # _current_progress =  - _current_progress
                else:
                    _d = None

                if _scan_finished is True:
                    break
        _t.join()
        return _d

    def _run(self, queue: Queue):
        """
        Runs the Nmap scan process and handles the output.

        This method starts the Nmap scan process with the specified targets and options.
        It continuously checks the status of the process and updates the progress queue.
        Once the process completes, it checks the return code and sends appropriate messages
        to the queue based on the result.

        Args:
            None

        Returns:
            None
        """
        np = NmapProcess(targets=self.target, options=self.scan_args)
        np.sudo_run_background()

        while np.is_running():
            queue.put(self._create_queue_message(
                QueueMsg.PROGRESS, self.target, int(float(np.progress))
            ))
            sleep(0.1)

        if np.rc != 0:
            queue.put(self._create_queue_message(
                QueueMsg.EXIT, self.target, np.rc
            ))
        else:
            parsed = NmapParser.parse(np.stdout)
            queue.put(self._create_queue_message(
                QueueMsg.DATA, self.target, parsed
            ))
            queue.put(self._create_queue_message(
                QueueMsg.EXIT, self.target, 1
            ))
    
    @staticmethod
    def _create_queue_message(msg_type: QueueMsg, target: str, msg):
        """
        Create a queue message based on the given message type, target, and message.

        Args:
            msg_type (QueueMsg): The type of the queue message.
            target (str): The target associated with the message.
            msg: The message content.

        Returns:
            dict: A dictionary representing the queue message.

        Raises:
            None

        """
        if msg_type == QueueMsg.PROGRESS:
            return {
                QMESSAGE_TYPE: QueueMsg.PROGRESS,
                QMESSAGE_HOST: target,
                QMESSAGE_MSG: msg
            }
        elif msg_type == QueueMsg.DATA:
            return {
                QMESSAGE_TYPE: QueueMsg.DATA,
                QMESSAGE_HOST: target,
                QMESSAGE_MSG: msg
            }
        else:
            return {
                QMESSAGE_TYPE: QueueMsg.EXIT,
                QMESSAGE_HOST: target,
                QMESSAGE_MSG: msg
            }

