import pytest
import sys
import os
from dataclasses import dataclass
import logging

TEST_DATA = "tests/unit/test_data"
DATABASE_PATH = f"{TEST_DATA}/test_db.db"

conf_module = type(sys)('deltascan.core.config')

conf_module.DATABASE = DATABASE_PATH
conf_module.DEFAULT_PROFILE = DEFAULT_PROFILE = {
    "name": "DEFAULT",
    "args": ""
}

conf_module.CSV = "csv"
conf_module.PDF = "pdf"
conf_module.HTML = "html"
conf_module.XML = "xml"

conf_module.ADDED = "added"
conf_module.CHANGED = "changed"
conf_module.REMOVED = "removed"

conf_module.LOG_CONF = {
    "level": logging.INFO,
    "filename": "error.log",
    "format": "%(asctime)s - %(levelname)s - %(message)s",
    "datefmt": "%Y-%m-%d %H:%M:%S",
}


@dataclass
class Config:
    is_interactive: bool
    output_file: str
    single: bool
    template_file: str
    import_file: str
    diff_files: str
    action: str
    profile: str
    conf_file: str
    verbose: str
    suppress: bool
    n_scans: str
    n_diffs: str
    fdate: str
    tdate: str
    port_type: str
    host: str
    db_path: str


conf_module.CONFIG_FILE_PATH = f"{TEST_DATA}/config.yaml"
conf_module.APP_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
conf_module.FILE_DATE_FORMAT = "%Y-%m-%d_%H:%M:%S"
conf_module.Config = Config


sys.modules['deltascan.core.config'] = conf_module


# Add here whatever you need to execute before the tests
def init():
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)


# Run cleanup actions
def cleanup():
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)


@pytest.fixture(autouse=True, scope="session")
def session_mgmt():
    init()
    yield
    cleanup()
