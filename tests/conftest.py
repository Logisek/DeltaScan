import pytest
import sys
import os

TEST_DATA = "tests/unit/test_data"
DATABASE_PATH = f"{TEST_DATA}/test_db.db"

conf_module = type(sys)('deltascan.core.config')
conf_module.DATABASE = DATABASE_PATH
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