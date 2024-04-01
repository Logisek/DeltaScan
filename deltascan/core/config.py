from dataclasses import dataclass

DEFAULT_PROFILE = {
    "name": "DEFAULT",
    "args": ""
}

APP_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
CONFIG_FILE_PATH = "config.yaml"
DATABASE = "deltascan.db"

CSV = "csv"
PDF = "pdf"
HTML = "html"
XML = "xml"

@dataclass
class Config:
    output_file: str
    template_file: str
    import_file: str
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