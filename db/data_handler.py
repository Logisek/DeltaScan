from . import db_manager
import logging

logging.basicConfig(filename="error.log", level=logging.DEBUG)


class DataHandler:
    def __init__(self):
        db_manager.initializeDatabase()

        if db_manager.getProfiles("default") is None:
            db_manager.setProfiles("default")

    def saveScan(self, scanData, args):
        # Remove runstats until implemented
        scanData.pop(0)

        scanListId = db_manager.setScanList("default", args)

        for host in scanData:
            try:
                db_manager.setScanResults(
                    scanListId,
                    host.get("address", "unknown"),
                    host.get("os", "unknown"),
                    host.get("ports", "unknown"),
                    host.get("status", "unknown"),
                )

            except Exception as e:
                logging.error("Error saving scan data: %s", str(e))
                return

        return
