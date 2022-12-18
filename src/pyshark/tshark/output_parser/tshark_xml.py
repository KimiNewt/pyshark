"""This module contains functions to turn TShark XML parts into Packet objects."""
import lxml.objectify

from pyshark.packet.layers.xml_layer import XmlLayer
from pyshark.packet.packet import Packet
from pyshark.packet.packet_summary import PacketSummary

from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser

# Prepare dictionary used with str.translate for removing invalid XML characters
DEL_BAD_XML_CHARS = {bad_char: None for bad_char in range(0x00, 0x20) if not bad_char in (0x09, 0x0a, 0x0d)}
DEL_BAD_XML_CHARS.update({bad_char: None for bad_char in range(0xd800, 0xe000)})
DEL_BAD_XML_CHARS.update({bad_char: None for bad_char in range(0xfffe, 0x10000)})


class TsharkXmlParser(BaseTsharkOutputParser):
    SUMMARIES_BATCH_SIZE = 64

    def __init__(self, parse_summaries=False):
        super().__init__()
        self._parse_summaries = parse_summaries
        self._psml_structure = None

    async def get_packets_from_stream(self, stream, existing_data, got_first_packet=True):
        if self._parse_summaries:
            existing_data = await self._get_psml_struct(stream)
        return await super().get_packets_from_stream(stream, existing_data, got_first_packet=got_first_packet)

    def _parse_single_packet(self, packet):
        return packet_from_xml_packet(packet, psml_structure=self._psml_structure)

    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Gets data containing a (part of) tshark xml.

        If the given tag is found in it, returns the tag data and the remaining data.
        Otherwise returns None and the same data.

        :param data: string of a partial tshark xml.
        :return: a tuple of (tag, data). tag will be None if none is found.
        """
        return _extract_tag_from_xml_data(data, tag_name=b"packet")

    async def _get_psml_struct(self, fd):
        """Gets the current PSML (packet summary xml) structure in a tuple ((None, leftover_data)),
        only if the capture is configured to return it, else returns (None, leftover_data).

        A coroutine.
        """
        initial_data = b""
        psml_struct = None

        # If summaries are read, we need the psdml structure which appears on top of the file.
        while not psml_struct:
            new_data = await fd.read(self.SUMMARIES_BATCH_SIZE)
            initial_data += new_data
            psml_struct, initial_data = _extract_tag_from_xml_data(initial_data, b"structure")
            if psml_struct:
                self._psml_structure = psml_structure_from_xml(psml_struct)
            elif not new_data:
                return initial_data
        return initial_data


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
        parser = lxml.objectify.makeparser(huge_tree=True, recover=True, encoding='utf-8')
        xml_pkt = xml_pkt.decode(errors='ignore').translate(DEL_BAD_XML_CHARS)
        xml_pkt = lxml.objectify.fromstring(xml_pkt.encode('utf-8'), parser)
    if psml_structure:
        return _packet_from_psml_packet(xml_pkt, psml_structure)
    return _packet_from_pdml_packet(xml_pkt)


def _packet_from_psml_packet(psml_packet, structure):
    return PacketSummary(structure, psml_packet.findall('section'))


def _packet_from_pdml_packet(pdml_packet):
    layers = [XmlLayer(proto) for proto in pdml_packet.proto]
    geninfo, frame, layers = layers[0], layers[1], layers[2:]
    return Packet(layers=layers, frame_info=frame, number=geninfo.get_field_value('num'),
                  length=geninfo.get_field_value('len'), sniff_time=geninfo.get_field_value('timestamp', raw=True),
                  captured_length=geninfo.get_field_value('caplen'),
                  interface_captured=frame.get_field_value('interface_id', raw=True))


def _extract_tag_from_xml_data(data, tag_name=b"packet"):
    """Gets data containing a (part of) tshark xml.

    If the given tag is found in it, returns the tag data and the remaining data.
    Otherwise returns None and the same data.

    :param data: string of a partial tshark xml.
    :param tag_name: A bytes string of the tag name
    :return: a tuple of (tag, data). tag will be None if none is found.
    """
    opening_tag = b"<" + tag_name + b">"
    closing_tag = opening_tag.replace(b"<", b"</")
    tag_end = data.find(closing_tag)
    if tag_end != -1:
        tag_end += len(closing_tag)
        tag_start = data.find(opening_tag)
        return data[tag_start:tag_end], data[tag_end:]
    return None, data
