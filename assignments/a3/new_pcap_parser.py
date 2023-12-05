import socket
import struct
from packet_struct import IP_Header, GlobalHeader, PacketHeader, UDPHeader, ICMPHeader, IPV4Header, TCP_Header, new_packet


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

            # storing packets lists
            src_packets = []
            dest_packets = []
            pcap_start_time = None

            packet_count = 0

            while True:
                packet_count += 1

                # Read packet header and extract timestamp and length
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break  # Exit the loop if no more packets are available

                # ts_sec, ts_usec, incl_len, _ = struct.unpack(
                #     self.byte_order + 'IIII', packet_header)

                # packet_data = f.read(incl_len)  # Read the packet data
                # eth_header = packet_data[:14]  # Extract Ethernet header
                # ip_packet = packet_data[14:]  # Extract IP packet

                # # Process only IPv4 packets
                # if eth_header[-2:] != b'\x08\x00':
                #     continue

                # # # Parse IP header information
                # ip_header_obj = IP_Header()
                # ip_header_obj.get_IP(ip_packet[12:16], ip_packet[16:20])
                # ip_header_obj.get_header_len(ip_packet[0:1])
                # ip_header_obj.get_total_len(ip_packet[2:4])
                # header_length = ip_header_obj.ip_header_len
                # protocol = ip_packet[9]  # Extract protocol type
                # ttl = ip_packet[8]  # Extract TTL

                # # Check if the packet is ICMP or UDP, otherwise skip it
                # if protocol not in [1, 17]:
                #     continue

                # # If the packet is the first one, set source and destination
                # if first_packet:
                #     self.source_node_ip = ip_header_obj.src_ip
                #     self.ultimate_destination_ip = ip_header_obj.dst_ip
                #     first_packet = False
                # else:
                #     if ttl > self.max_ttl and self.is_valid(ip_packet):
                #         self.max_ttl = ttl

                #         # Check if the packet is a response from an intermediate node
                #     if ttl <= self.max_ttl:
                #         # Extract identification and fragment offset
                #         identification = struct.unpack('!H', ip_packet[4:6])[0]
                #         flags_and_fragment_offset = struct.unpack(
                #             '!H', ip_packet[6:8])[0]
                #         # The last 13 bits are the fragment offset
                #         fragment_offset = flags_and_fragment_offset & 0x1FFF

                #         # Handle fragments
                #         if identification not in self.fragmented_packets:
                #             self.fragmented_packets[identification] = DatagramFragment(
                #             )
                #         self.fragmented_packets[identification].count += 1
                #         self.fragmented_packets[identification].offset = fragment_offset
                #         self.fragmented_packets[identification].send_times.append(
                #             ts_sec + ts_usec / 1_000_000)

                #         # Track the intermediate IPs if this is a "Time Exceeded" response
                #         # ICMP with "Time Exceeded" type
                #         if protocol == 1 and ip_packet[header_length] == 11:
                #             self.intermediate_ips_with_ttl[ttl] = ip_header_obj.src_ip

                # self.protocol_values[protocol] = protocol_mapping.get(
                #     protocol, "Unknown")

                packet = new_packet()
                packet.set_header(packet_header)
                packet.set_number(packet_count)

                incl_len = packet.header.incl_len

                if pcap_start_time is None:
                    seconds = packet.header.ts_sec
                    microseconds = packet.header.ts_usec
                    pcap_start_time = round(
                        seconds + microseconds * 0.000001, 6)

                packet.set_data(f.read(incl_len))

                packet.set_ipv4()

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

            if any(p.icmp.type_num == 8 for p in dest_packets):

                icmp_all = dest_packets
                src = []
                dest = []

                for p in icmp_all:
                    if p.icmp.type_num == 8:
                        src.append(p)
                    if p.icmp.type_num == 11 or p.icmp.type_num == 0:  # or p.icmp.type_num == 3:
                        dest.append(p)

                intermediate_ips = []
                intermediate_packets = []
                rtt_dict = {}

                for p1 in src:
                    for p2 in dest:
                        if p1.icmp.sequence == p2.icmp.sequence:
                            if p2.ipv4.src_ip not in intermediate_ips:
                                intermediate_ips.append(p2.ipv4.src_ip)
                                intermediate_packets.append(p2)
                                rtt_dict[p2.ipv4.src_ip] = []

                            # RTT Calculation
                            p1.set_timestamp(pcap_start_time)
                            p2.set_timestamp(pcap_start_time)
                            rtt_dict[p2.ipv4.src_ip].append(
                                p2.timestamp-p1.timestamp)

            # Linux
            else:
                intermediate_ips = []
                intermediate_packets = []
                rtt_dict = {}

                for p1 in src_packets:
                    for p2 in dest_packets:
                        if p1.udp.src_port == p2.icmp.src_port:  # and p2.icmp.type_num == 11 and p2.icmp.code == 0
                            if p2.ipv4.src_ip not in intermediate_ips:
                                intermediate_ips.append(p2.ipv4.src_ip)
                                intermediate_packets.append(p2)
                                rtt_dict[p2.ipv4.src_ip] = []

                            # RTT Calculation
                            p1.set_timestamp(pcap_start_time)
                            p2.set_timestamp(pcap_start_time)
                            rtt_dict[p2.ipv4.src_ip].append(
                                p2.timestamp-p1.timestamp)

            identity_dict = {}

            # figure out fragmented datagrams
            for packet in src_packets:
                if packet.ipv4.identification not in identity_dict:
                    identity_dict[packet.ipv4.identification] = []

                identity_dict[packet.ipv4.identification].append(packet)

            # check fragment count
            frag_count = 0
            for identity in identity_dict:
                if len(identity_dict[identity]) > 1:
                    frag_count += 1

            # After processing all packets, print the results
            print(f"The IP address of the source node: {self.source_node_ip}")
            print(
                f"The IP address of the ultimate destination node: {self.ultimate_destination_ip}")
            print("Length of intermediate_ips:", len(intermediate_ips))

            print("The IP addresses of the intermediate nodes:")
            for x in range(len(intermediate_ips)-1):
                print(f"\t router {x+1}: {intermediate_ips[x]}")

            print("\nThe values in protocol field of IP headers:")
            for protocol, name in self.protocol_values.items():
                print(f"\t{protocol}: {name}")

            for datagram_id, fragment in self.fragments.items():
                print(f"Datagram ID: {datagram_id}")
                print(
                    f"The number of fragments created from the original datagram is: {fragment.count}")
                # Convert offset to bytes
                print(
                    f"The offset of the last fragment is: {fragment.offset * 8}")

        return None

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
