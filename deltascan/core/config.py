from dataclasses import dataclass
import logging

DEFAULT_PROFILE = {
    "name": "DEFAULT",
    "args": ""
}

APP_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
FILE_DATE_FORMAT = '%Y-%m-%d_%H:%M:%S'
CONFIG_FILE_PATH = "config.yaml"
DATABASE = "deltascan.db"

CSV = "csv"
PDF = "pdf"
HTML = "html"
XML = "xml"

ADDED = "added"
CHANGED = "changed"
REMOVED = "removed"

ERROR_LOG = "error.log"
LOG_CONF = {
    "level": logging.INFO,
    "filename": ERROR_LOG,
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
    verbose: bool
    suppress: bool
    n_scans: str
    n_diffs: str
    fdate: str
    tdate: str
    port_type: str
    host: str
    db_path: str


BANNER = """
     _____        _
    (____ \      | |_                             
     _   \ \ ____| | |_  ____  ___  ____ ____ ____  
    | |   | / _  ) |  _)/ _  |/___)/ ___) _  |  _ \ 
    | |__/ ( (/ /| | |_( ( | |___ ( (__( ( | | | | |
    |_____/ \____)_|\___)_||_(___/ \____)_||_|_| |_|    

    {}
 -------------------------------------------------------
 - Scans in Db            :  {}   
 - Profiles in Db         :  {}                                    
 - Profile                :  {}                          
 - Configuration file     :  {}
 - Output file            :  {}
 - Database path          :  {}
 -------------------------------------------------------
"""

VERSION_STR = """Deltascan
  Network scanning wrapper for nmap with diff checking capabilities
  Version: {}"""