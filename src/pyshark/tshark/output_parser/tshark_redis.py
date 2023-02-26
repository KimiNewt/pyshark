import json
import os

import redis

from packaging import version

from pyshark.packet.layers.json_layer import JsonLayer
from pyshark.packet.packet import Packet
#from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser
from pyshark.tshark.output_parser.tshark_json import TsharkJsonParser, duplicate_object_hook
from pyshark.tshark import tshark

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False

class TsharkRedisParser(TsharkJsonParser):
    """
    Based on TsharkJsonParser for dev purposes.
    """
    
    def __init__(self, tshark_version=None):
        super().__init__()
        self._tshark_version = tshark_version

    def _parse_single_packet(self, packet):
        json_has_duplicate_keys = tshark.tshark_supports_duplicate_keys(self._tshark_version)
        return json_packet_to_redis(packet)

def json_packet_to_redis(json_pkt):
    r=redis.Redis(host="redis.local", port=6379, db=0)
    return True
