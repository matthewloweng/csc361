import struct
import os
import sys

from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection


def print_results():

    print(f"The IP address of the source node: ")
    print(f"The IP address of the ultimate destination node: ")
    print(f"The IP addresses of th eintermediate destination nodes:")

    print(f"The values in the protocol field of IP headers:")
    return 0
