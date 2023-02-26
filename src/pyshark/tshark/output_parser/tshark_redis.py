import json
import os

import redis

from packaging import version

from pyshark.packet.layers.json_layer import JsonLayer
from pyshark.packet.packet import Packet
from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser
from pyshark.tshark import tshark

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False


class TsharkRedisParser(BaseTsharkOutputParser):
    pass
