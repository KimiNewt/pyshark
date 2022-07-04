import os

from configparser import ConfigParser

import pyshark


fp_config_path = os.path.join(os.getcwd(), 'config.ini')  # get config from the current directory
pyshark_config_path = os.path.join(os.path.dirname(pyshark.__file__), 'config.ini')


def get_config():
    if os.path.exists(fp_config_path):
        CONFIG_PATH = fp_config_path
    elif os.path.exists(pyshark_config_path):
        CONFIG_PATH = pyshark_config_path
    else:
        return None
        
    config = ConfigParser()
    config.read(CONFIG_PATH)
    return config
