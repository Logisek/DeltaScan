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


class DScanSchemaException(DScanException):
    pass


class DScanExporterError(DScanException):
    pass


class DScanImportError(DScanException):
    pass


class DScanExporterErrorProcessingData(DScanExporterError):
    pass


class DScanExporterSchemaException(DScanExporterError):
    pass


class DScanExporterFileExtensionNotSpecified(DScanExporterError):
    pass


class DScanImportFileError(DScanImportError):
    pass


class DScanImportFileExtensionError(DScanImportError):
    pass


class DScanImportDataError(DScanImportError):
    pass


class DScanResultsSchemaException(DScanSchemaException):
    pass


class DScanPermissionDeniedError(DScanSchemaException):
    pass


class DScanNmapScanException(DScanNmapException):
    pass


class DScanInputValidationException(DScanNmapException):
    pass


class DScanRDBMSException(DScanException):
    pass


class DScanRDBMSEntryNotFound(DScanRDBMSException):
    pass


class DScanRDBMSErrorCreatingEntry(DScanRDBMSException):
    pass


class DScanMethodNotImplemented(DScanException):
    pass

class DScanResultsParsingError(DScanException):
    pass