import os

from configparser import ConfigParser

import pyshark

CONFIG_PATH = os.path.join(os.path.dirname(pyshark.__file__), 'config.ini')


def get_config():
    config = ConfigParser()
    config.read(CONFIG_PATH)
    return config
