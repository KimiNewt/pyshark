import json

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False

from pyshark.packet.layers.ek_layer import EkLayer
from pyshark.packet.packet import Packet


def packet_from_ek_packet(json_pkt):
    if USE_UJSON:
        pkt_dict = ujson.loads(json_pkt)
    else:
        pkt_dict = json.loads(json_pkt.decode('utf-8'))

    # We use the frame dict here and not the object access because it's faster.
    frame_dict = pkt_dict['layers'].pop('frame')
    layers = []
    for layer in frame_dict['frame_frame_protocols'].split(':'):
        layer_dict = pkt_dict['layers'].pop(layer, None)
        if layer_dict is not None:
            layers.append(EkLayer(layer, layer_dict))
    # Add all leftovers
    for name, layer in pkt_dict['layers'].items():
        layers.append(EkLayer(name, layer))

    return Packet(layers=layers, frame_info=EkLayer('frame', frame_dict),
                  number=int(frame_dict.get('frame_frame_number', 0)),
                  length=int(frame_dict['frame_frame_len']),
                  sniff_time=frame_dict['frame_frame_time_epoch'],
                  interface_captured=frame_dict.get('rame_frame_interface_id'))
