"""
Test suite for Enhanced FileCapture with expanded tshark -r capabilities.
"""
import pytest
import tempfile
import pathlib
from unittest.mock import patch, MagicMock

# Import our enhanced classes
from pyshark.capture.enhanced_file_capture import EnhancedFileCapture, FileCapture
from pyshark.capture.enhancements import TimestampFormat, SecondsFormat, ExportProtocol


class TestEnhancedFileCapture:
    """Test enhanced tshark -r capabilities."""
    
    def setup_method(self):
        """Setup test fixtures."""
        # Create a mock pcap file for testing
        self.test_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        self.test_pcap.write(b'fake pcap data for testing')
        self.test_pcap.close()
        
    def teardown_method(self):
        """Clean up test fixtures."""
        pathlib.Path(self.test_pcap.name).unlink(missing_ok=True)
        
    def test_two_pass_analysis_parameter_validation(self):
        """Test that read_filter requires two_pass_analysis=True."""
        
        # Should raise ValueError when read_filter is used without two_pass_analysis
        with pytest.raises(ValueError, match="read_filter requires two_pass_analysis=True"):
            EnhancedFileCapture(
                input_file=self.test_pcap.name,
                read_filter="tcp.port == 443",
                two_pass_analysis=False
            )
            
        # Should work when both are set correctly
        try:
            cap = EnhancedFileCapture(
                input_file=self.test_pcap.name,
                read_filter="tcp.port == 443",
                two_pass_analysis=True
            )
            assert cap.two_pass_analysis == True
            assert cap.read_filter == "tcp.port == 443"
        except ValueError:
            pytest.fail("Should not raise ValueError when parameters are correct")
            
    def test_timestamp_parameter_validation(self):
        """Test timestamp parameter validation."""
        
        # Should raise ValueError when precision is set without format
        with pytest.raises(ValueError, match="timestamp_precision requires timestamp_format"):
            EnhancedFileCapture(
                input_file=self.test_pcap.name,
                timestamp_precision=6
            )
            
        # Should raise ValueError for invalid precision values
        with pytest.raises(ValueError, match="timestamp_precision must be between 0 and 9"):
            EnhancedFileCapture(
                input_file=self.test_pcap.name,
                timestamp_format=TimestampFormat.ABSOLUTE,
                timestamp_precision=10
            )
            
    def test_enhanced_parameters_in_get_parameters(self):
        """Test that enhanced parameters are correctly added to tshark command."""
        
        cap = EnhancedFileCapture(
            input_file=self.test_pcap.name,
            two_pass_analysis=True,
            read_filter="tcp.port == 443",
            timestamp_format=TimestampFormat.ABSOLUTE,
            timestamp_precision=6,
            seconds_format=SecondsFormat.HMS,
            color_output=True,
            no_duplicate_keys=True,
            session_auto_reset=5000
        )
        
        params = cap.get_parameters()
        
        # Check that enhanced parameters are included
        assert "-2" in params
        assert "-WARNING" in params
        assert "tcp.port == 443" in params
        assert "-ta.6" in params
        assert "-u" in params
        assert "hms" in params
        assert "--color" in params
        assert "--no-duplicate-keys" in params
        assert "-M" in params
        assert "5000" in params
        
    def test_export_objects_parameter_validation(self):
        """Test export objects parameter validation."""
        
        with tempfile.TemporaryDirectory() as temp_dir:
            export_config = {
                ExportProtocol.HTTP: temp_dir + "/http/",
                ExportProtocol.SMB: temp_dir + "/smb/"
            }
            
            cap = EnhancedFileCapture(
                input_file=self.test_pcap.name,
                export_objects=export_config
            )
            
            params = cap.get_parameters()
            
            # Check that export parameters are included
            assert "--export-objects" in params
            assert any("http," in p for p in params)
            assert any("smb," in p for p in params)
            
    def test_hexdump_and_output_enhancements(self):
        """Test hexdump and output enhancement parameters."""
        
        cap = EnhancedFileCapture(
            input_file=self.test_pcap.name,
            hexdump_mode="ascii,delimit",
            color_output=True,
            temp_directory="/tmp/pyshark_test"
        )
        
        params = cap.get_parameters()
        
        assert "--hexdump" in params
        assert "ascii,delimit" in params
        assert "--color" in params
        assert "--temp-dir" in params
        assert "/tmp/pyshark_test" in params
        
    @patch('subprocess.run')
    def test_export_objects_to_directory(self, mock_run):
        """Test runtime object export functionality."""
        
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Export completed"
        mock_run.return_value.stderr = ""
        
        cap = EnhancedFileCapture(input_file=self.test_pcap.name)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            result = cap.export_objects_to_directory(ExportProtocol.HTTP, temp_dir)
            
            assert result["success"] == True
            assert "Objects exported" in result["message"]
            
            # Verify subprocess was called with correct parameters
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]  # First positional argument (command list)
            assert "--export-objects" in call_args
            assert f"http,{temp_dir}" in call_args
            
    @patch('subprocess.run')
    def test_export_tls_session_keys(self, mock_run):
        """Test TLS session key export functionality."""
        
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Keys exported"
        mock_run.return_value.stderr = ""
        
        cap = EnhancedFileCapture(input_file=self.test_pcap.name)
        
        with tempfile.NamedTemporaryFile(suffix='.keys') as temp_keyfile:
            result = cap.export_tls_session_keys_to_file(temp_keyfile.name)
            
            assert result["success"] == True
            assert "TLS keys exported" in result["message"]
            
            # Verify subprocess was called correctly
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "--export-tls-session-keys" in call_args
            assert temp_keyfile.name in call_args
            
    @patch('subprocess.run')  
    def test_get_statistics(self, mock_run):
        """Test statistics generation functionality."""
        
        mock_stats_output = """
        ===================================================================
        Protocol Hierarchy Statistics
        Filter: 
        
        eth                                      frames:100 bytes:15000
          ip                                     frames:90  bytes:13500
            tcp                                  frames:70  bytes:10500
              http                               frames:30  bytes:4500
            udp                                  frames:20  bytes:3000
              dns                                frames:10  bytes:1500
        ===================================================================
        """
        
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = mock_stats_output
        mock_run.return_value.stderr = ""
        
        cap = EnhancedFileCapture(input_file=self.test_pcap.name)
        
        stats = cap.get_statistics("io,phs")
        
        assert "Protocol Hierarchy Statistics" in stats
        assert "frames:100" in stats
        
        # Verify correct tshark command
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "-z" in call_args
        assert "io,phs" in call_args
        assert "-q" in call_args  # Quiet mode for stats only
        
    def test_backward_compatibility(self):
        """Test that FileCapture still works with enhanced features."""
        
        # Original FileCapture should work as before
        cap = FileCapture(input_file=self.test_pcap.name)
        assert isinstance(cap, EnhancedFileCapture)
        
        # Ind should support new features
        enhanced_cap = FileCapture(
            input_file=self.test_pcap.name,
            two_pass_analysis=True,
            timestamp_format=TimestampFormat.EPOCH
        )
        
        params = enhanced_cap.get_parameters()
        assert "-2" in params
        assert "-te" in params
        
    def test_enum_values(self):
        """Test that enum values are correct."""
        
        # Test TimestampFormat values
        assert TimestampFormat.ABSOLUTE.value == "a"
        assert TimestampFormat.EPOCH.value == "e"
        assert TimestampFormat.ELTVE.value == "r"
        
        # Test SecondsFormat values
        assert SecondsFormat.SECODS.value == "s"
        assert SecondsFormat.HMS.value == "hms"
        
        # Test ExportProtocol values
        assert ExportProtocol.HTTP.value == "http"
        assert ExportProtocol.SMB.value == "smb"
        assert ExportProtocol.TFTP.value == "tftp"


if __name__ == "__main__":
    # un tests
    pytest.main([__file__, "-v"])