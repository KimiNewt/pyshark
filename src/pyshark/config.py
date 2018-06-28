import pyshark
import py
import os

CONFIG_PATH = os.path.join(os.path.dirname(pyshark.__file__), 'config.ini')

def get_config():
    return py.iniconfig.IniConfig(CONFIG_PATH)
