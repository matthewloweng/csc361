import sys
import re
import struct
from packet_struct import IP_Header, TCP_Header, new_packet
from final_pcap_parser import PcapParser

from print_output import print_results


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path_to_cap_file>")
        sys.exit(1)

    cap_file = sys.argv[1]
    pcap_file_path = f"PcapTracesAssignment3/{cap_file}"
    # pcap_parser = PcapParser(pcap_file_path)
    pcap_parser = PcapParser(cap_file)
    results = pcap_parser.parse()

    print_results(results)

    # pcap_parser.parse()


if __name__ == "__main__":
    main()
