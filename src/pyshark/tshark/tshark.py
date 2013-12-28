"""
Module used for the actual running of TShark
"""
import os
import sys
import subprocess

from pyshark.config import get_config


class TSharkNotFoundException(Exception):
    pass


def get_tshark_path():
    """
    Finds the path of the tshark executable according to the list in the configuration.

    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    config = get_config()
    if sys.platform.startswith('win'):
        possible_paths = config.get('tshark', 'windows_paths').split(',')
    else:
        possible_paths = config.get('tshark', 'linux_paths').split(',')

    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException('TShark not found in the following locations: ' + ', '.join(possible_paths) +
                                  ' Either place tshark there or add more paths to the config file.')


def read_cap(cap_path):
    tshark_path = get_tshark_path()


def tshark_xml_from_pcap(pcap_path):
    """
    Creates a TShark XML from a pcap file. Returns the XML.

    :param pcap_path: Path of the pcap file.
    :return: A string of a PDML XML.
    """
    p = subprocess.Popen([get_tshark_path(),
                      '-T', 'pdml',
                      '-r', pcap_path],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
    return p.stdout.read()