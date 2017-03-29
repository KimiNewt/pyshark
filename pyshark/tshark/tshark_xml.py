"""
This module contains functions to turn TShark XML parts into Packet objects.
"""
import lxml.objectify
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from pyshark.packet.packet_summary import PacketSummary


def psml_structure_from_xml(psml_structure):
    if not isinstance(psml_structure, lxml.objectify.ObjectifiedElement):
        psml_structure = lxml.objectify.fromstring(psml_structure)
    return psml_structure.findall('section')


def packet_from_xml_packet(xml_pkt, psml_structure=None):
    """
    Gets a TShark XML packet object or string, and returns a pyshark Packet objec.t

    :param xml_pkt: str or xml object.
    :param psml_structure: a list of the fields in each packet summary in the psml data. If given, packets will
    be returned as a PacketSummary object.
    :return: Packet object.
    """
    if not isinstance(xml_pkt, lxml.objectify.ObjectifiedElement):
        parser = lxml.objectify.makeparser(huge_tree=True)
        xml_pkt = lxml.objectify.fromstring(xml_pkt, parser)
    if psml_structure:
        return _packet_from_psml_packet(xml_pkt, psml_structure)
    return _packet_from_pdml_packet(xml_pkt)


def _packet_from_psml_packet(psml_packet, structure):
    return PacketSummary(structure, psml_packet.findall('section'))


def _packet_from_pdml_packet(pdml_packet):
    layers = [Layer(proto) for proto in pdml_packet.proto]
    geninfo, frame, layers = layers[0], layers[1], layers[2:]
    return Packet(layers=layers, frame_info=frame, number=geninfo.get_field_value('num'),
                  length=geninfo.get_field_value('len'), sniff_time=geninfo.get_field_value('timestamp', raw=True),
                  captured_length=geninfo.get_field_value('caplen'),
                  interface_captured=frame.get_field_value('interface_id', raw=True))