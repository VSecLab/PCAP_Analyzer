from port_extraction import *
from pcap_processing import *
from data_model import *
import sys
import constants as c

def main():
    print("Hello World!")
    print("Pcap directory: " + c.PCAP_DIR)
    print("Scapy Version: " + str(scapy.__version__))
    print("Python Version: " + str(sys.version))

    create_data_payload_csv("PCAP/anonymized_28_06_1000-1330.pcap", "anon/anon_metadata_28_06_1000-1330.csv", "anon/anon_payload_28_06_1000-1330.csv")
    create_data_payload_csv("PCAP/anonymized_28_06_1330-1830.pcap", "anon/anon_metadata_28_06_1330-1830.csv", "anon/anon_payload_28_06_1330-1830.csv")
    create_data_payload_csv("PCAP/anonymized_29_06_1000-1330.pcap", "anon/anon_metadata_29_06_1000-1330.csv", "anon/anon_payload_29_06_1000-1330.csv")
    create_data_payload_csv("PCAP/anonymized_29_06_1330-1830.pcap", "anon/anon_metadata_29_06_1330-1830.csv", "anon/anon_payload_29_06_1330-1830.csv")

if __name__ == "__main__":
    main()
