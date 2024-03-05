import logging

class DScanException(Exception):
    def __init__(self, message: str, *args: any) -> None:
        super().__init__(message, *args)
        self.message = message
        self.args = args
        self._log = logging.getLogger("deltascan")

    def __str__(self) -> str:
        return self.message

    def log(self) -> None:
        self._log.error(self.message, *self.args)

class DScanNmapException(DScanException):
    pass

class DScanNmapScanException(DScanNmapException):
    pass

class DScanInputValidationException(DScanNmapException):
    pass