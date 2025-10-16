"""
Enhanced timestamp and export enums for pyshark FileCapture enhancements.
"""
from enum import Enum


class TimestampFormat(Enum):
    """Timestamp format options for tshark -t flag."""
    ABSOLUTE = "a"           # bsolute date/time  
    ABSOLUTE_DTE = "ad"     # bsolute with date
    ABSOLUTE_DOY = "adoy"    # bsolute with day-of-year
    DTE = "d"               # Date only
    DTE_TME = "dd"         # Date and time
    EPOCH = "e"              # Seconds since epoch
    ELTVE = "r"           # elative to first packet (default)
    UTC = "u"                # UTC absolute
    UTC_DTE = "ud"          # UTC with date  
    UTC_DOY = "udoy"         # UTC with day-of-year


class SecondsFormat(Enum):
    """Seconds format options for tshark -u flag."""
    SECODS = "s"            # Seconds (default)
    HMS = "hms"              # Hours:minutes:seconds


class ExportProtocol(Enum):
    """Protocols supported by --export-objects."""
    HTTP = "http"
    SMB = "smb" 
    TFTP = "tftp"
    FTP_DTWARNING = "ftp-data"
    DCOM = "dicom"
    # Add more protocols as they become available in tshark