import json
import os

from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False

from pyshark.packet.layers.ek_layer import EkLayer
from pyshark.packet.packet import Packet

_ENCODED_OS_LINESEP = os.linesep.encode()


class TsharkEkJsonParser(BaseTsharkOutputParser):

    def _parse_single_packet(self, packet):
        return packet_from_ek_packet(packet)

    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Returns a packet's data and any remaining data after reading that first packet"""
        start_index = 0
        data = data.lstrip()
        if data.startswith(b'{"ind'):
            # Skip the 'index' JSONs, generated for Elastic.
            # See: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16656
            start_index = data.find(_ENCODED_OS_LINESEP) + 1
        linesep_location = data.find(_ENCODED_OS_LINESEP, start_index)
        if linesep_location == -1:
            return None, data

        return data[start_index:linesep_location], data[linesep_location + 1:]


def packet_from_ek_packet(json_pkt):
    if USE_UJSON:
        pkt_dict = ujson.loads(json_pkt)
    else:
        pkt_dict = json.loads(json_pkt.decode('utf-8'))

    # We use the frame dict here and not the object access because it's faster.
    layers = pkt_dict['layers']
    frame_dict = layers.pop('frame')
    
    # Sort the frame protocol layers first
    ek_layers = []        
    for name in frame_dict['frame_frame_protocols'].split(':'):
        layer = layers.get(name)
        if isinstance(layer, list):
            ek_layers.append(EkLayer(name, layer.pop(0)))
        elif layers.pop(name, None) is not None:
            ek_layers.append(EkLayer(name, layer))
        
    # Add all leftovers
    for name, layer in layers.items():
        if isinstance(layer, list):
            for sub_layer in layer:
                ek_layers.append(EkLayer(name, sub_layer) )
        else:
            ek_layers.append(EkLayer(name, layer))

    return Packet(layers=ek_layers, frame_info=EkLayer('frame', frame_dict),
                  number=int(frame_dict.get('frame_frame_number', 0)),
                  length=int(frame_dict['frame_frame_len']),
                  sniff_time=frame_dict['frame_frame_time_epoch'],
                  interface_captured=frame_dict.get('rame_frame_interface_id'))
