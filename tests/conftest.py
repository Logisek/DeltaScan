import pytest
import sys
import os
from dataclasses import dataclass

TEST_DATA = "tests/unit/test_data"
DATABASE_PATH = f"{TEST_DATA}/test_db.db"

conf_module = type(sys)('deltascan.core.config')

conf_module.DATABASE = DATABASE_PATH
conf_module.DEFAULT_PROFILE = DEFAULT_PROFILE = {
    "name": "DEFAULT",
    "args": ""
}

@dataclass
class Config:
    output_file: str
    action: str
    profile: str
    conf_file: str
    verbose: str
    n_scans: str
    n_diffs: str
    date: str
    port_type: str
    host: str

conf_module.CONFIG_FILE_PATH = f"{TEST_DATA}/config.yaml"
conf_module.APP_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
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