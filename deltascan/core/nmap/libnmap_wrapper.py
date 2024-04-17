from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from queue import Queue
from threading import Thread
from time import sleep
from enum import Enum
from contextlib import nullcontext
from deltascan.core.config import LOG_CONF
import logging


class QueueMsg(Enum):
    DATA = "data"
    PROGRESS = "progress"
    EXIT = "exit"


QMESSAGE_TYPE = "type"
QMESSAGE_HOST = "host"
QMESSAGE_MSG = "msg"


class LibNmapWrapper:
    """
    A wrapper class for performing Nmap scans.

    This class provides methods to perform Nmap scans on specified targets using the given scan arguments.
    It handles the Nmap scan process, manages the progress, and returns the scan results.

    Attributes:
        target (str): The target to scan.
        scan_args (str): The arguments to pass to the Nmap scanner.
        ui_context (optional): The UI context for the scan.
        logger: The logger instance for logging scan errors.

    """

    target: str
    scan_args: str

    def __init__(self, target: str, scan_args: str, ui_context=None, logger=None, name=None):
        """
        Initializes a new instance of the LibNmapWrapper class.

        Args:
            target (str): The target to scan.
            scan_args (str): The arguments to pass to the Nmap scanner.
            ui_context (optional): The UI context for the scan.
            logger: The logger instance for logging scan errors.

        """
        self.target = target
        self.scan_args = scan_args
        self.ui_context = ui_context
        self.name = name

    @classmethod
    def scan(cls, target: str, scan_args: str, ui_context=None, logger=None, name=None):
        """
        Perform a scan using Nmap.

        Args:
            target (str): The target to scan.
            scan_args (str): The arguments to pass to Nmap.
            ui_context (Optional): The UI context.
            logger (Optional): The logger to use for logging.

        Returns:
            The result of the scan.

        Raises:
            Exception: If an error occurs during the scan.
        """
        cls.logger = logger if logger is not None else logging.basicConfig(**LOG_CONF)
        instance = cls(target, scan_args, ui_context, logger=cls.logger, name=name)
        try:
            return instance._scan()
        except Exception as e:
            instance.logger.error(f"An error occurred: {str(e)}")
            raise e

    def _scan(self):
        """
        Perform the scan.

        This method starts a new thread to run the scan and continuously listens for incoming messages from the scan thread.
        It updates the progress bar and displays the stdout output in the UI context if available.

        Returns:
            list: The scan results.
        """
        _q = Queue()
        _t = Thread(target=self._run, args=(_q,))
        _t.start()
        _d = []
        _scan_finished = False

        with self.ui_context["ui_live"] if self.ui_context is not None and self.ui_context["ui_live"].is_started else nullcontext() as _:
            _current_progress = 0
            _current_stdout = None
            _stdout_changed = False
            while True:
                _incoming_msg = _q.get()
                if _incoming_msg[QMESSAGE_TYPE] == QueueMsg.DATA:
                    _d = _incoming_msg[QMESSAGE_MSG]
                    _current_progress = 100
                elif _incoming_msg[QMESSAGE_TYPE] == QueueMsg.EXIT:
                    _scan_finished = True
                    _current_progress = 100
                elif _incoming_msg[QMESSAGE_TYPE] == QueueMsg.PROGRESS:
                    _current_progress = _incoming_msg[QMESSAGE_MSG]["progress"]
                    if _current_stdout != _incoming_msg[QMESSAGE_MSG]["stdout"]:
                        _stdout_changed = True
                        _current_stdout = _incoming_msg[QMESSAGE_MSG]["stdout"]
                    else:
                        _stdout_changed = False
                else:
                    _d = None

                if self.ui_context is not None or self.ui_context["ui_live"].is_started is True:
                    self.ui_context["ui_instances"]["progress_bar"][str(self.name)]["instance"].update(
                                        self.ui_context["ui_instances"]["progress_bar"][str(self.name)]["id"],
                                        completed=_current_progress
                                    )

                    # if _stdout_changed is True:
                    #     self.ui_context["ui_instances"]["text"][str(self.name)]["instance"].truncate(1)
                    #     if _scan_finished is not True:
                    #        self.ui_context["ui_instances"]["text"][str(self.name)]["instance"].append(_current_stdout[-600:])

                if _scan_finished is True:
                    break

        _t.join()
        return _d

    def _run(self, queue: Queue):
        """
        Runs the Nmap scan process and sends progress, data, and exit messages to the queue.

        Args:
            queue (Queue): The queue to send the messages to.

        Returns:
            None
        """
        np = NmapProcess(targets=self.target, options=self.scan_args)
        np.sudo_run_background()

        while np.is_running() or np.is_successful() is False or np.rc != 0:
            queue.put(self._create_queue_message(
                QueueMsg.PROGRESS, self.target, {
                    "progress": int(float(np.progress)),
                    "stdout": np.stdout
                }
            ))
            sleep(0.5)

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
