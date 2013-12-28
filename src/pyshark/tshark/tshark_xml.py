"""
This module contains functions to turn TShark XML parts into Packet objects.
"""
import lxml.objectify
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
from pyshark.tshark.tshark import tshark_xml_from_pcap


def packets_from_file(cap_or_xml):
    """
    Gets an xml file data and returns the raw xml and a list of packets.

    :return tuple of (raw_xml_file, packets)
    """
    beginning = cap_or_xml.read(5)
    if beginning == '<?xml':
        # It's an xml file.
        xml_data = beginning + cap_or_xml.read()
    else:
        # We assume it's a PCAP file and use tshark to get the XML.
        xml_data = tshark_xml_from_pcap(cap_or_xml.name)

    return xml_data, packets_from_xml(xml_data)


def packet_from_xml_packet(xml_pkt):
    """
    Gets a TShark XML packet object or string, and returns a pyshark Packet objec.t

    :param xml_pkt: str or xml object.
    :return: Packet object.
    """
    if not isinstance(xml_pkt, lxml.objectify.ObjectifiedElement):
        xml_pkt = lxml.objectify.fromstring(xml_pkt)
    layers = [Layer(proto) for proto in xml_pkt.proto]
    geninfo, frame, layers = layers[0], layers[1], layers[2:]
    frame.raw_mode = True
    return Packet(layers=layers, length=geninfo.get_field_value('len'), sniff_time=geninfo.get_field_value('timestamp'),
                  captured_length=geninfo.get_field_value('caplen'), interface_captured=frame.get_field_value('interface_id'))


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