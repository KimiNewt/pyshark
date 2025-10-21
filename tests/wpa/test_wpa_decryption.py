
import pyshark

def main():
    wpa_capture_path = "tests/data/wpa-Induction.pcap"
    wpa_decryption_key = "Induction:Induction"
    # Use pyshark to decrypt WPA traffic
    with pyshark.FileCapture(
        wpa_capture_path,
        decryption_key=wpa_decryption_key,
        encryption_type="wpa-pwd"
    ) as cap:
        packets = list(cap)
    print(f"Decrypted {len(packets)} packets.")
    # Optionally, print details of the first packet
    if packets:
        print(packets[0])

if __name__ == "__main__":
    main()
