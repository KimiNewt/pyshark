import os
import pyshark
import unittest

class TestFileCaptures(unittest.TestCase):
    def setUp(self):
        self.infile_dir = os.path.dirname(__file__)
        self.infile_path = os.path.join(self.infile_dir, 'capture_test.pcapng')
        self.cap = pyshark.FileCapture(self.infile_path, lazy=False)
    
    def tearDown(self):
        self.cap.close()
    
    def test_count_packets(self):
        """Test to make sure the right number of packets are read from a known
           capture"""
        packet_count = sum(1 for packet in self.cap)
        self.assertEqual(packet_count, 24)
    
    def test_sum_lengths(self):
        """Test to make sure that the right packet length is being read from
           tshark's output by comparing the aggregate length of all packets
           to a known value"""
        total_length = sum(int(packet.length) for packet in self.cap)
        self.assertEqual(total_length, 2178)
    
    def test_layers(self):
        """Test to make sure the correct protocols are reported for known
           packets"""
        packet_indexes = (0, 5, 6, 13, 14, 17, 23)
        test_values = [self.cap[i].highest_layer for i in packet_indexes]
        known_values = ['DNS', 'DNS', 'ICMP', 'ICMP', 'TCP', 'HTTP', 'TCP']
        self.assertEqual(test_values, known_values)
    
    def test_ethernet(self):
        """Test to make sure Ethernet fields are being read properly by comparing
           packet dissection results to known values"""
        packet = self.cap[0]
        test_values = packet.eth.addr, packet.eth.dst
        known_values = ('00:00:bb:10:20:10', '00:00:bb:02:04:01')
        self.assertEqual(test_values, known_values)
    
    def test_icmp(self):
        """Test to make sure ICMP fields are being read properly by comparing
           packet dissection results to known values"""
        packet = self.cap[11]
        resptime = packet.icmp.resptime
        self.assertEqual(resptime, '1.667')

if __name__ == '__main__':
    unittest.main()