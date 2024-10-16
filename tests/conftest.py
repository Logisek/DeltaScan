# DeltaScan - Network scanning tool
#     Copyright (C) 2024 Logisek
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>

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
conf_module.JSON = "json"

conf_module.ADDED = "added"
conf_module.CHANGED = "changed"
conf_module.REMOVED = "removed"

conf_module.LOG_CONF = {
    "level": logging.INFO,
    "filename": "error.log",
    "format": "%(asctime)s - %(levelname)s - %(message)s",
    "datefmt": "%Y-%m-%d %H:%M:%S",
}
conf_module.ERROR_LOG = "error.log"


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
    n_scans: str
    n_diffs: str
    fdate: str
    tdate: str
    port_type: str
    host: str
    db_path: str


conf_module.CONFIG_FILE_PATH = f"{TEST_DATA}/config.yaml"
conf_module.APP_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
conf_module.APP_DATE_FORMAT_NO_TIME = "%Y-%m-%d"
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
