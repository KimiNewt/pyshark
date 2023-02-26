import json
import os

import redis

from packaging import version

from pyshark.packet.layers.json_layer import JsonLayer
from pyshark.packet.packet import Packet
from pyshark.tshark.output_parser.tshark_json import TsharkJsonParser
from pyshark.tshark import tshark

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False

class TsharkRedisParser(TsharkJsonParser):
    
    def __init__(self, tshark_version=None, redis_host=None, redis_key=None):
        super().__init__()
        self._tshark_version = tshark_version
        self.redis_host=redis_host
        self.redis_key=redis_key

    def _parse_single_packet(self, packet):
        return json_packet_to_redis(packet, self.redis_host, self.redis_key)

def json_packet_to_redis(json_pkt, redis_host, redis_key):
    r=redis.Redis(host=redis_host, port=6379, db=0)
    r.lpush(redis_key, json_pkt)
    return True
