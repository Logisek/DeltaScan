from dataclasses import dataclass

DEFAULT_PROFILE = {
    "name": "DEFAULT",
    "args": ""
}

APP_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
CONFIG_FILE_PATH = "config.yaml"
DATABASE = "deltascan.db"

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