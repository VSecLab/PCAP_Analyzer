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

    extract_pcap("28_06_1000-1330.pcap")
    extract_pcap("28_06_1330-1830.pcap")
    extract_pcap("29_06_1000-1330.pcap")
    extract_pcap("29_06_1330-1830.pcap")

if __name__ == "__main__":
    main()
