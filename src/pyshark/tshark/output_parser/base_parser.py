class BaseTsharkOutputParser:
    DEFAULT_BATCH_SIZE = 2 ** 16

    async def get_packets_from_stream(self, stream, existing_data, got_first_packet=True):
        """A coroutine which returns a single packet if it can be read from the given StreamReader.

        :return a tuple of (packet, remaining_data). The packet will be None if there was not enough XML data to create
        a packet. remaining_data is the leftover data which was not enough to create a packet from.
        :raises EOFError if EOF was reached.
        """
        # yield each packet in existing_data
        packet, existing_data = self._extract_packet_from_data(existing_data,
                                                               got_first_packet=got_first_packet)
        if packet:
            packet = self._parse_single_packet(packet)
            return packet, existing_data

        new_data = await stream.read(self.DEFAULT_BATCH_SIZE)
        existing_data += new_data

        if not new_data:
            raise EOFError()
        return None, existing_data

    def _parse_single_packet(self, packet):
        raise NotImplementedError()

    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Returns a packet's data and any remaining data after reading that first packet"""
        raise NotImplementedError()
