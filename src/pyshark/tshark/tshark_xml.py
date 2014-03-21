"""
This module contains functions to turn TShark XML parts into Packet objects.
"""
import lxml.objectify
from pyshark.packet.field import Field
from pyshark.packet.packet import Packet


def packet_from_xml_packet(xml_pkt):
    """
    Gets a TShark XML packet object or string, and returns a pyshark Packet objec.t

    :param xml_pkt: str or xml object.
    :return: Packet object.
    """
    if not isinstance(xml_pkt, lxml.objectify.ObjectifiedElement):
        xml_pkt = lxml.objectify.fromstring(xml_pkt)
    layers = [Field(proto) for proto in xml_pkt.proto]
    geninfo, frame, layers = layers[0], layers[1], layers[2:]
    frame.raw_mode = True
    return Packet(layers=layers, length=geninfo['len'].get_Attr('value'), sniff_time=geninfo['timestamp'].get_Attr('value'),
                  captured_length=geninfo['caplen'].get_Attr('value'), interface_captured=None)


def packets_from_xml(xml_data):
    """
    Returns a list of Packet objects from a TShark XML.

    :param xml_data: str containing the XML.
    """
    pdml = lxml.objectify.fromstring(xml_data)
    packets = []

    for xml_pkt in pdml.getchildren():
        packets += [packet_from_xml_packet(xml_pkt)]
    return packets
