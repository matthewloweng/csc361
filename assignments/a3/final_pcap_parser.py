import socket
import struct
from packet_struct import GlobalHeader, UDPHeader, ICMPHeader, TCP_Header, new_packet, IP_Header


class DatagramFragment:
    # Stores information about a fragmented datagram
    def __init__(self):
        self.count = 0  # Number of fragments in the datagram
        self.offset = 0  # Offset of the last fragment
        self.send_times = []  # Timestamps when each fragment was sent


class Packet:
    # Represents a network packet with essential information
    def __init__(self):
        self.fragment_id = 0  # Unique identifier of the fragment
        self.source_ip_address = ""  # Source IP address
        self.timestamp = 0  # Time when the packet was received
        self.ttl = 0  # Time to live value of the packet
        self.ttl_adj = 0  # Adjusted TTL value based on processing logic


class PcapParser:
    # Parser for reading and interpreting pcap files
    def __init__(self, filename):
        self.filename = filename
        self.byte_order = '<'  # Assume little endian byte order initially
        self.start_timestamp = None  # Timestamp of the first packet
        self.source_node_ip = ""  # IP address of the source node
        self.ultimate_destination_ip = ""  # IP address of the final destination
        self.fragments = {}  # Stores details of each datagram fragment
        self.protocol_values = {}  # Stores unique protocol values for IP headers
        self.rtt_data = {}  # Round-trip times for different IP addresses
        self.intermediate_ips_with_ttl = {}  # Intermediate IPs mapped with TTL values
        self.original_datagrams = {}  # Original datagrams before being fragmented
        self.packet_count = 0  # Counter for processed packets
        self.fragmented_packets = {}
        self.max_ttl = 0

    def parse(self):
        # Open the pcap file for reading

        with open(self.filename, 'rb') as f:
            global_header = f.read(24)
            magic_number = struct.unpack('I', global_header[:4])[0]

            # Determine the byte order and time resolution based on magic number
            if magic_number in (0xa1b2c3d4, 0x4d3cb2a1):
                self.byte_order = '>'
                self.time_resolution = 'nanoseconds' if magic_number == 0x4d3cb2a1 else 'microseconds'
            elif magic_number in (0xd4c3b2a1, 0xa1b23c4d):
                self.byte_order = '<'
                self.time_resolution = 'nanoseconds' if magic_number == 0xa1b23c4d else 'microseconds'
            else:
                print("Unknown magic number in pcap file.")
                return None

            # Map protocol numbers to names
            protocol_mapping = {1: "ICMP", 17: "UDP"}
            self.protocol_values = {}
            first_packet = True  # Flag to identify the first packet
            send_times = {}  # Dictionary to track send times of packets
            DNS_PORT = 53  # Port number used for DNS
            packets = 0

            # storing packets lists
            src_packets = []
            dest_packets = []
            datagram_fragments = {}
            pcap_start_time = None

            while True:

                packets += 1

                # Read packet header and extract timestamp and length
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break  # Exit the loop if no more packets are available

                packet = new_packet()
                packet.set_header(packet_header)
                packet.set_number(packets)

                incl_len = packet.incl_len

                if pcap_start_time is None:
                    seconds = packet.ts_sec
                    microseconds = packet.ts_usec
                    pcap_start_time = round(
                        seconds + microseconds * 0.000001, 6)

                packet.set_data(f.read(incl_len))

                packet.set_ip_header()

                id = packet.IP_header.id
                fragment_offset = packet.IP_header.fragment_offset

                if id not in datagram_fragments:
                    datagram_fragments[id] = {
                        'count': 0, 'last_offset': 0}

                datagram_fragments[id]['count'] += 1

                if fragment_offset > datagram_fragments[id]['last_offset']:
                    datagram_fragments[id]['last_offset'] = fragment_offset

                if packet.IP_header.protocol == 1:
                    packet.set_icmp()
                    dest_packets.append(packet)
                    self.protocol_values[1] = 'ICMP'

                if packet.IP_header.protocol == 17:
                    packet.set_udp()
                    src_packets.append(packet)
                    if not 33434 <= packet.udp.dst_port <= 33529:
                        continue
                    self.protocol_values[17] = 'UDP'

                if packet.IP_header.protocol not in protocol_mapping:
                    continue

            found_icmp_type_8 = False

            for packet in dest_packets:
                if packet.icmp.type_num == 8:
                    found_icmp_type_8 = True
                    break

            if found_icmp_type_8:

                src_packets = []
                icmp = dest_packets
                dest_packets = []

                for packet in icmp:
                    if packet.icmp.type_num == 8:
                        src_packets.append(packet)
                    elif packet.icmp.type_num in [0, 11]:
                        dest_packets.append(packet)

                intermediate_ips = []
                intermediate_packets = []
                rtts = {}

                # Calculate RTT and populate intermediate IPs
                for src_packet in src_packets:
                    for dest_packet in dest_packets:
                        if dest_packet.icmp.sequence == src_packet.icmp.sequence:
                            if dest_packet.IP_header.src_ip not in intermediate_ips:
                                intermediate_ips.append(
                                    dest_packet.IP_header.src_ip)
                                intermediate_packets.append(dest_packet)
                                rtts[dest_packet.IP_header.src_ip] = []

                            # RTT Calculation
                            src_packet.set_timestamp(pcap_start_time)
                            dest_packet.set_timestamp(pcap_start_time)
                            rtt_val = dest_packet.timestamp - src_packet.timestamp
                            rtts[dest_packet.IP_header.src_ip].append(
                                rtt_val)

            else:
                intermediate_ips = []
                intermediate_packets = []
                rtts = {}

                for src_packet in src_packets:
                    for dest_packet in dest_packets:
                        if src_packet.udp.src_port == dest_packet.icmp.src_port:
                            if dest_packet.IP_header.src_ip not in intermediate_ips:
                                intermediate_ips.append(
                                    dest_packet.IP_header.src_ip)
                                intermediate_packets.append(dest_packet)
                                rtts[dest_packet.IP_header.src_ip] = []

                            # RTT Calculation
                            src_packet.set_timestamp(pcap_start_time)
                            dest_packet.set_timestamp(pcap_start_time)
                            rtts[dest_packet.IP_header.src_ip].append(
                                dest_packet.timestamp-src_packet.timestamp)

            id = {}

            # figure out fragmented datagrams
            for packet in src_packets:
                if packet.IP_header.id not in id:
                    id[packet.IP_header.id] = []

                id[packet.IP_header.id].append(packet)

            # fragment count
            fragment_count = 0
            for identity in id:
                if len(id[identity]) > 1:
                    fragment_count += 1

        return {
            "source_node_ip": self.source_node_ip,
            "ultimate_destination_ip": self.ultimate_destination_ip,
            "src_packets": src_packets,
            "intermediate_ips": intermediate_ips,
            "protocol_values": self.protocol_values,
            "id": id,
            "rtt_dict": rtts,
            "fragment_count": fragment_count
        }

    # Method to check if the IP packet contains UDP or ICMP echo request (type 8)

    def is_valid(self, ip_header):
        # Extract the protocol field from the IP header
        # Assuming ip_header is a byte array of the IP packet
        protocol = ip_header[9]

        # Check if the protocol is UDP
        if protocol == 17:  # 17 is the protocol number for UDP
            return True

        # If the protocol is ICMP, check if it's an echo request (type 8)
        elif protocol == 1:  # 1 is the protocol number for ICMP
            # ICMP type is the first byte of the ICMP header
            icmp_type = ip_header[20]
            return icmp_type == 8  # Return True if it's an echo request

        return False  # If neither, return False
