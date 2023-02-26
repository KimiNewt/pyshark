import json
import os

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


class TsharkJsonParser(BaseTsharkOutputParser):

    def __init__(self, tshark_version=None):
        super().__init__()
        self._tshark_version = tshark_version

    def _parse_single_packet(self, packet):
        json_has_duplicate_keys = tshark.tshark_supports_duplicate_keys(self._tshark_version)
        return packet_from_json_packet(packet, deduplicate_fields=json_has_duplicate_keys)

    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Returns a packet's data and any remaining data after reading that first packet"""
        tag_start = 0
        if not got_first_packet:
            tag_start = data.find(b"{")
            if tag_start == -1:
                return None, data
        packet_separator, end_separator, end_tag_strip_length = self._get_json_separators()
        found_separator = None

        tag_end = data.find(packet_separator)
        if tag_end == -1:
            # Not end of packet, maybe it has end of entire file?
            tag_end = data.find(end_separator)
            if tag_end != -1:
                found_separator = end_separator
        else:
            # Found a single packet, just add the separator without extras
            found_separator = packet_separator

        if found_separator:
            tag_end += len(found_separator) - end_tag_strip_length
            return data[tag_start:tag_end].strip().strip(b","), data[tag_end + 1:]
        return None, data

    def _get_json_separators(self):
        """"Returns the separators between packets in a JSON output

        Returns a tuple of (packet_separator, end_of_file_separator, characters_to_disregard).
        The latter variable being the number of characters to ignore in order to pass the packet (i.e. extra newlines,
        commas, parenthesis).
        """
        if not self._tshark_version or self._tshark_version >= version.parse("3.0.0"):
            return f"{os.linesep}  }},{os.linesep}".encode(), f"}}{os.linesep}]".encode(), 1 + len(os.linesep)
        else:
            return f"}}{os.linesep}{os.linesep}  ,".encode(), f"}}{os.linesep}{os.linesep}]".encode(), 1


def duplicate_object_hook(ordered_pairs):
    """Make lists out of duplicate keys."""
    json_dict = {}
    for key, val in ordered_pairs:
        existing_val = json_dict.get(key)
        if not existing_val:
            json_dict[key] = val
        else:
            if isinstance(existing_val, list):
                existing_val.append(val)
            else:
                json_dict[key] = [existing_val, val]

    return json_dict


def packet_from_json_packet(json_pkt, deduplicate_fields=True):
    """Creates a Pyshark Packet from a tshark json single packet.

    Before tshark 2.6, there could be duplicate keys in a packet json, which creates the need for
    deduplication and slows it down significantly.
    """
    if deduplicate_fields:
        # NOTE: We can use ujson here for ~25% speed-up, however since we can't use hooks in ujson
        # we lose the ability to view duplicates. This might still be a good option later on.
        pkt_dict = json.loads(json_pkt.decode('utf-8'), object_pairs_hook=duplicate_object_hook)
    else:
        if USE_UJSON:
            pkt_dict = ujson.loads(json_pkt)
        else:
            pkt_dict = json.loads(json_pkt.decode('utf-8'))
    # We use the frame dict here and not the object access because it's faster.
    frame_dict = pkt_dict['_source']['layers'].pop('frame')
    layers = []
    for layer in frame_dict['frame.protocols'].split(':'):
        layer_dict = pkt_dict['_source']['layers'].pop(layer, None)
        if layer_dict is not None:
            layers.append(JsonLayer(layer, layer_dict))
    # Add all leftovers
    for name, layer in pkt_dict['_source']['layers'].items():
        layers.append(JsonLayer(name, layer))

    return Packet(layers=layers, frame_info=JsonLayer('frame', frame_dict),
                  number=int(frame_dict.get('frame.number', 0)),
                  length=int(frame_dict['frame.len']),
                  sniff_time=frame_dict['frame.time_epoch'],
                  interface_captured=frame_dict.get('frame.interface_id'))
