try:
    import ujson as json
except ImportError:
    import json

from pyshark.packet.layer import JsonLayer
from pyshark.packet.packet import Packet


def packet_from_json_packet(json_pkt):
    pkt_dict = json.loads(json_pkt)
    # We use the frame dict here and not the object access because it's faster.
    frame_dict = pkt_dict['_source']['layers']['frame']
    layers = []
    for layer in frame_dict['frame.protocols'].split(':'):
        layer_dict = pkt_dict['_source']['layers'].get(layer)
        if layer_dict is not None:
            layers.append(JsonLayer(layer, layer_dict))

    return Packet(layers=layers, frame_info=JsonLayer('frame', frame_dict),
                  number=int(frame_dict['frame.number']),
                  length=int(frame_dict['frame.len']),
                  sniff_time=frame_dict['frame.time'],
                  interface_captured=frame_dict['frame.interface_id'])
