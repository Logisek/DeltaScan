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


# ------------------------------------ Application exceptions ------------------------------------ #

class AppExceptions:
    class DScanAppError(DScanException):
        pass

    class DScanImportError(DScanAppError):
        pass

    class DScanExportError(DScanAppError):
        pass

    class DScanProfileNotFoundException(DScanAppError):
        pass

    class DScanSchemaException(DScanAppError):
        pass

    class DScanResultsSchemaException(DScanAppError):
        pass

    class DScanPermissionDeniedError(DScanAppError):
        pass

    class DScanMethodNotImplemented(DScanAppError):
        pass

    class DScanResultsParsingError(DScanAppError):
        pass

    class DScanInputValidationException(DScanAppError):
        pass

    class DScanEntryNotFound(DScanAppError):
        pass

# ------------------------------------ Nmap scanner exceptions ------------------------------------ #


class NmapScannerExceptions:

    class DScanNmapException(DScanException):
        pass

    class DScanNmapScanException(DScanNmapException):
        pass

# ------------------------------------ Exporter exceptions ------------------------------------ #


class ExporterExceptions:
    class DScanExporterError(DScanException):
        pass

    class DScanExporterErrorProcessingData(DScanExporterError):
        pass

    class DScanExporterSchemaException(DScanExporterError):
        pass

    class DScanExporterFileExtensionNotSpecified(DScanExporterError):
        pass

# ------------------------------------ Importer exception ------------------------------------ #


class ImporterExceptions:
    class DScanImportError(DScanException):
        pass

    class DScanImportFileError(DScanImportError):
        pass

    class DScanImportFileExtensionError(DScanImportError):
        pass

    class DScanImportDataError(DScanImportError):
        pass

# ------------------------------------ Store exception ------------------------------------ #


class StoreExceptions:
    class DScanStoreSException(DScanException):
        pass

    class DScanEntryNotFound(DScanStoreSException):
        pass

    class DScanErrorCreatingEntry(DScanStoreSException):
        pass

    class DScanInputSchemaError(DScanStoreSException):
        pass


# ------------------------------------ Database exception ------------------------------------ #


class DatabaseExceptions:
    class DScanRDBMSException(DScanException):
        pass

    class DScanRDBMSEntryNotFound(DScanRDBMSException):
        pass

    class DScanRDBMSErrorCreatingEntry(DScanRDBMSException):
        pass

    class DScanPermissionDeniedError(DScanRDBMSException):
        pass
