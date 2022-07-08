from pathlib import Path

from configparser import ConfigParser

import pyshark


fp_config_path = Path.cwd() / 'config.ini'  # get config from the current directory
pyshark_config_path = Path(pyshark.__file__).parent / 'config.ini'


def get_config():
    if fp_config_path.exists():
        config_path = fp_config_path
    elif pyshark_config_path.exists():
        config_path = pyshark_config_path
    else:
        return None
        
    config = ConfigParser()
    config.read(config_path)
    return config
