import struct
import os
import sys

from packet_struct import IP_Header, TCP_Header, new_packet
from connection import Connection


def print_results(parsing_results):

    source_node_ip = parsing_results["source_node_ip"]
    ultimate_destination_ip = parsing_results["ultimate_destination_ip"]
    src_packets = parsing_results["src_packets"]
    intermediate_ips = parsing_results["intermediate_ips"]
    protocol_values = parsing_results["protocol_values"]
    id = parsing_results["id"]
    rtt_dict = parsing_results["rtt_dict"]
    fragment_count = parsing_results["fragment_count"]

    print(f"The IP address of the source node: {source_node_ip}")
    print(
        f"The IP address of the ultimate destination node: {ultimate_destination_ip}")
    print('The IP address of the source node:',
          src_packets[0].IP_header.src_ip)
    print('The IP address of ultimate destination node:',
          src_packets[0].IP_header.dst_ip)
    print("Length of intermediate_ips:", len(intermediate_ips))

    print("The IP addresses of the intermediate nodes:")
    for ttl in range(len(intermediate_ips)-1):
        print(f"\t router {ttl+1}: {intermediate_ips[ttl]}")

    print("\nThe values in protocol field of IP headers:")
    for p, name in protocol_values.items():
        print(f"\t{p}: {name}")

    if fragment_count != 0:
        for identity, packets in id.items():
            fragment_count = len(packets)
            last_offset = max(
                packet.IP_header.fragment_offset for packet in packets)
            print(
                f"\nThe number of fragments created from the original datagram {identity} is: {fragment_count}")
            print(f"The offset of the last fragment is: {last_offset}\n")
    else:
        print('\nThe number of fragments created from the original datagram is: 1\n')
        print('The offset of the last fragment is: 0\n\n')

    # RTT average time and standard deviation
    for i in range(len(intermediate_ips)):
        avg = round(
            sum(rtt_dict[intermediate_ips[i]]) / len(rtt_dict[intermediate_ips[i]]), 6)
        std = round((sum(pow(x-avg, 2) for x in rtt_dict[intermediate_ips[i]]) / len(
            rtt_dict[intermediate_ips[i]]))**(1/2), 6)
        print('The avg RTT between', src_packets[0].IP_header.src_ip, 'and',
              intermediate_ips[i], 'is:', avg, 'ms, the s.d. is:', std, 'ms')
