try:
    import ujson as json
except ImportError:
    import json

from pyshark.packet.layer import JsonLayer
from pyshark.packet.packet import Packet


def packet_from_json_packet(json_pkt):
    pkt_dict = json.loads(json_pkt)
    layers = {name: JsonLayer(name, layer)
              for name, layer in pkt_dict['_source']['layers'].items()}
    frame = layers.pop('frame')
    protocol_order = frame.protocols.split(':')
    layers = [layers[proto] for proto in protocol_order if proto in layers]

    return Packet(layers=layers, frame_info=frame, number=int(frame.number),
                  length=int(frame.len),
                  sniff_time=frame.time,
                  interface_captured=frame.interface_id)
