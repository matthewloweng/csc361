import sys
import re
import struct
from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection
from pcap_parser import PcapParser

from print_output import print_results


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <path_to_cap_file>")
        sys.exit(1)

    cap_file = sys.argv[1]


if __name__ == "__main__":
    main()
