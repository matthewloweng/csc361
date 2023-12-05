import socket
import struct
from packet_struct import IP_Header


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

            while True:
                # Read packet header and extract timestamp and length
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break  # Exit the loop if no more packets are available

                ts_sec, ts_usec, incl_len, _ = struct.unpack(
                    self.byte_order + 'IIII', packet_header)
                timestamp = ts_sec + ts_usec * 0.000001  # Calculate timestamp

                # Set the start timestamp if this is the first packet
                if self.start_timestamp is None:
                    self.start_timestamp = timestamp

                timestamp -= self.start_timestamp  # Adjust timestamp relative to the first packet
                packet_data = f.read(incl_len)  # Read the packet data
                eth_header = packet_data[:14]  # Extract Ethernet header
                ip_packet = packet_data[14:]  # Extract IP packet

                # Process only IPv4 packets
                if eth_header[-2:] != b'\x08\x00':
                    continue

                # Parse IP header information
                ip_header_obj = IP_Header()
                ip_header_obj.get_IP(ip_packet[12:16], ip_packet[16:20])
                ip_header_obj.get_header_len(ip_packet[0:1])
                ip_header_obj.get_total_len(ip_packet[2:4])
                header_length = ip_header_obj.ip_header_len
                protocol = ip_packet[9]  # Extract protocol type

                # Extract source and destination IP addresses
                source_ip_address = ip_header_obj.src_ip
                destination_ip_address = ip_header_obj.dst_ip

                # Handling IP fragmentation
                fragment_id = ip_packet[4:6]  # Extract fragment ID
                # Extract flags and offset
                flags, fragment_offset = ip_packet[6:10]
                if fragment_id not in self.fragments:
                    self.fragments[fragment_id] = DatagramFragment()
                self.fragments[fragment_id].count += 1
                self.fragments[fragment_id].offset = max(
                    self.fragments[fragment_id].offset, fragment_offset)

                # Tracking protocol types
                protocol = ip_packet[9]  # Extract protocol
                self.protocol_values[protocol] = protocol_mapping.get(
                    protocol, "Unknown")

                # Skip packets that are not ICMP or UDP
                if protocol not in [1, 17]:
                    continue

                # Record the protocol type
                self.protocol_values[protocol] = protocol_mapping.get(
                    protocol, "Unknown")

                # Set source and destination IPs for the first packet
                if first_packet:
                    self.source_node_ip = ip_header_obj.src_ip
                    self.ultimate_destination_ip = ip_header_obj.dst_ip
                    first_packet = False

                # Extract datagram ID, flags, and fragment offset for fragmentation handling
                datagram_id = struct.unpack('!H', ip_packet[4:6])[0]
                flags, fragment_offset = struct.unpack('!HH', ip_packet[6:10])
                more_fragments = flags & 0x2000  # Check if more fragments flag is set
                fragment_offset = fragment_offset & 0x1FFF  # Get actual offset value

                # Process UDP packets
                if protocol == 17:  # UDP
                    udp_header = ip_packet[header_length:header_length + 8]
                    src_port, dest_port = struct.unpack('!HH', udp_header[:4])

                    # Filter out non-traceroute UDP packets and DNS packets
                    if not (33434 <= dest_port <= 33529) or src_port == DNS_PORT or dest_port == DNS_PORT:
                        continue

                    # Store send time for traceroute UDP packets
                    send_times[src_port] = timestamp

                # Process ICMP packets
                elif protocol == 1:  # ICMP
                    icmp_packet = ip_packet[header_length:]
                    icmp_type, _ = struct.unpack('!BB', icmp_packet[:2])

                    # Handle ICMP Echo request
                    if icmp_type == 8:  # Echo request
                        _, icmp_seq = struct.unpack('!HH', icmp_packet[4:8])
                        # Store send time for ICMP Echo request packets
                        send_times[icmp_seq] = timestamp

                    # Handle ICMP Time Exceeded messages
                    # Time Exceeded Message
                    elif icmp_type == 11 and icmp_packet[1] == 0:
                        encapsulated_ip_packet = icmp_packet[8:]
                        if len(encapsulated_ip_packet) > 20:
                            # Extract encapsulated IP header and protocol
                            encapsulated_ip_header_obj = IP_Header()
                            encapsulated_ip_header_obj.get_IP(
                                encapsulated_ip_packet[12:16], encapsulated_ip_packet[16:20])
                            encapsulated_ip_header_obj.get_header_len(
                                encapsulated_ip_packet[0:1])
                            encapsulated_protocol = encapsulated_ip_packet[9]

                            # Process encapsulated UDP packets within ICMP
                            if encapsulated_protocol == 17:
                                udp_header = encapsulated_ip_packet[
                                    encapsulated_ip_header_obj.ip_header_len:encapsulated_ip_header_obj.ip_header_len + 8]
                                _, dest_port = struct.unpack(
                                    '!HH', udp_header[:4])

                                if 33434 <= dest_port <= 33529:
                                    # Store intermediate router information
                                    intermediate_ip = ip_header_obj.src_ip
                                    orig_ttl = ip_packet[8]
                                    if orig_ttl not in self.intermediate_ips_with_ttl:
                                        self.intermediate_ips_with_ttl[orig_ttl] = set(
                                        )
                                    self.intermediate_ips_with_ttl[orig_ttl].add(
                                        intermediate_ip)
                                # Handle fragmentation
                if not more_fragments or fragment_offset != 0:
                    # If the packet is a fragment, update the fragments dictionary
                    if datagram_id not in self.fragments:
                        self.fragments[datagram_id] = DatagramFragment()
                    self.fragments[datagram_id].count += 1
                    self.fragments[datagram_id].offset = max(
                        self.fragments[datagram_id].offset, fragment_offset)

            # After processing all packets, print the results
            print(f"The IP address of the source node: {self.source_node_ip}")
            print(
                f"The IP address of the ultimate destination node: {self.ultimate_destination_ip}")
            print("The IP addresses of the intermediate nodes:")
            for ttl in sorted(self.intermediate_ips_with_ttl):
                for ip in self.intermediate_ips_with_ttl[ttl]:
                    print(f"\t router {ttl}: {ip}")

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
