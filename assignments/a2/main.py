import struct
import os
import sys
from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection
from pcap_parser import PcapParser
from print_output import (print_connection_details, print_statistics,
                          print_connection_counts, print_detailed_complete_tcp_statistics)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_analyzer.py <path_to_cap_file>")
        sys.exit(1)

    cap_file = sys.argv[1]
    connections = {}

    parser = PcapParser(cap_file, connections)
    parser.parse()

    # Print connection details
    print_connection_details(connections)

    # Get connection counts and print them
    complete_connections, reset_connections, open_connections = parser.count_connections()
    print_connection_counts(complete_connections,
                            reset_connections, open_connections)

    # Get detailed stats for complete TCP connections and print them
    detailed_stats = parser.compute_detailed_stats()
    print_detailed_complete_tcp_statistics(*detailed_stats)


if __name__ == "__main__":
    main()
