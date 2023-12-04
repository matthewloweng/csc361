import socket
import struct
from packet_struct import IP_Header


class DatagramFragment:
    def __init__(self):
        self.count = 0  # Number of fragments for the datagram
        self.offset = 0  # Offset of the last fragment
        self.send_times = []  # Send times of the fragments


class Packet:
    def __init__(self):
        self.fragment_id = 0  # Identifier of the fragment
        self.source_ip_address = ""  # Source IP address of the packet
        self.timestamp = 0  # Timestamp of the packet
        self.ttl = 0  # Time to live value of the packet
        self.ttl_adj = 0  # Adjusted TTL value based on the processing logic


class PcapParser:
    def __init__(self, filename):
        self.filename = filename
        self.byte_order = '<'  # Default to little endian
        self.start_timestamp = None
        self.source_node_ip = ""
        self.ultimate_destination_ip = ""
        self.intermediate_ips = set()
        self.fragments = {}  # Key: Datagram ID, Value: Fragment details
        self.protocol_values = {}  # To store unique protocol values
        self.rtt_data = {}  # Key: IP Address, Value: List of RTTs
        self.intermediate_ips_with_ttl = {}  # Key: TTL, Value, Set of IPs
        self.original_datagrams = {}

    def parse(self):
        with open(self.filename, 'rb') as f:
            global_header = f.read(24)
            magic_number = struct.unpack('I', global_header[:4])[0]
            # print(magic_number)
            # Check and set byte order and time resolution based on magic number
            if magic_number in (0xa1b2c3d4, 0x4d3cb2a1):
                self.byte_order = '>'
                self.time_resolution = 'nanoseconds' if magic_number == 0x4d3cb2a1 else 'microseconds'
            elif magic_number in (0xd4c3b2a1, 0xa1b23c4d):
                self.byte_order = '<'
                self.time_resolution = 'nanoseconds' if magic_number == 0xa1b23c4d else 'microseconds'
            else:
                print("Unknown magic number in pcap file.")
                return None

            protocol_mapping = {1: "ICMP", 17: "UDP"}
            self.protocol_values = {}
            first_packet = True  # Initializing before loop
            send_times = {}  # Dictionary to keep track of when packets are sent, keyed by IP id
            rtts = {}  # Dictionary to track RTTs
            DNS_PORT = 53
            while True:
                packet_header = f.read(16)
                if len(packet_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, _ = struct.unpack(
                    self.byte_order + 'IIII', packet_header)
                timestamp = ts_sec + ts_usec * 0.000001

                if self.start_timestamp is None:
                    self.start_timestamp = timestamp

                timestamp -= self.start_timestamp

                packet_data = f.read(incl_len)
                eth_header = packet_data[:14]
                ip_packet = packet_data[14:]

                if eth_header[-2:] == b'\x08\x00':  # IPv4
                    ip_header_obj = IP_Header()
                    ip_header_obj.get_IP(ip_packet[12:16], ip_packet[16:20])
                    ip_header_obj.get_header_len(ip_packet[0:1])
                    ip_header_obj.get_total_len(ip_packet[2:4])

                    header_length = ip_header_obj.ip_header_len

                    protocol = ip_packet[9]

                    if protocol not in [1, 17]:
                        continue

                    if protocol in [1, 17]:
                        self.protocol_values[protocol] = protocol_mapping.get(
                            protocol, "Unknown")

                    # if protocol not in self.protocol_values:
                    #     self.protocol_values[protocol] = protocol_mapping.get(
                    #         protocol, "Unknown")

                    if not (protocol == 1 or protocol == 17):
                        continue

                    if protocol == 17:  # UDP
                        udp_header = ip_packet[header_length:header_length + 8]
                        src_port, dest_port = struct.unpack(
                            '!HH', udp_header[:4])
                        if not (33434 <= dest_port <= 33529):
                            continue

                        # Skip DNS packets
                        if src_port == DNS_PORT or dest_port == DNS_PORT:
                            continue
                        self.original_datagrams[dest_port] = ip_packet[8]

                    if first_packet:
                        self.source_node_ip = ip_header_obj.src_ip
                        first_packet = False
                    # Identify the ultimate destination IP, which should be the destination IP of the first packet
                    if not self.ultimate_destination_ip:
                        self.ultimate_destination_ip = ip_header_obj.dst_ip

                        # Check for fragmentation
                    datagram_id = struct.unpack('!H', ip_packet[4:6])[0]
                    flags, fragment_offset = struct.unpack(
                        '!HH', ip_packet[6:10])
                    do_not_fragment = flags & 0x4000
                    more_fragments = flags & 0x2000
                    fragment_offset = fragment_offset & 0x1FFF

                    # If this is the first fragment, store its send time
                    if fragment_offset == 0:
                        send_times[datagram_id] = timestamp

                    # If this is the last fragment, store the fragment count and last offset
                    if not more_fragments:
                        if datagram_id not in self.fragments:
                            self.fragments[datagram_id] = {
                                'count': 0, 'last_offset': 0}
                        self.fragments[datagram_id]['count'] += 1
                        # Convert to bytes
                        self.fragments[datagram_id]['last_offset'] = fragment_offset * 8

                    # Check for ICMP protocol (value 1) to find intermediate routers
                    if protocol == 1:  # ICMP protocol
                        icmp_packet = ip_packet[header_length:]
                        icmp_type, icmp_code = struct.unpack(
                            '!BB', icmp_packet[:2])
                        if icmp_type == 11 and icmp_code == 0:  # Time Exceeded Message
                            # Extract encapsulated IP packet
                            encapsulated_ip_packet = icmp_packet[8:]
                            # Check if it's long enough to contain a header
                            if len(encapsulated_ip_packet) > 20:
                                encapsulated_ip_header_obj = IP_Header()
                                encapsulated_ip_header_obj.get_IP(
                                    encapsulated_ip_packet[12:16], encapsulated_ip_packet[16:20])
                                encapsulated_ip_header_obj.get_header_len(
                                    encapsulated_ip_packet[0:1])

                                encapsulated_header_length = encapsulated_ip_header_obj.ip_header_len
                                encapsulated_protocol = encapsulated_ip_packet[9]

                                if encapsulated_protocol == 17:  # Encapsulated UDP
                                    # Check for UDP header
                                    if len(encapsulated_ip_packet) >= encapsulated_header_length + 8:
                                        udp_header = encapsulated_ip_packet[
                                            encapsulated_header_length:encapsulated_header_length + 8]
                                        _, dest_port = struct.unpack(
                                            '!HH', udp_header[:4])

                                        # Check if this is the UDP packet we are interested in
                                        if 33434 <= dest_port <= 33529:
                                            # Store intermediate router information
                                            intermediate_ip = ip_header_obj.src_ip
                                            orig_ttl = ip_packet[8]
                                            if orig_ttl not in self.intermediate_ips_with_ttl:
                                                self.intermediate_ips_with_ttl[orig_ttl] = set(
                                                )
                                            self.intermediate_ips_with_ttl[orig_ttl].add(
                                                intermediate_ip)

                            # OLD CODE
                            # orig_datagram_port =
                            # ttl = ip_packet[8]
                            # intermediate_ip = ip_header_obj.src_ip
                            # orig_ip_packet = icmp_packet[8:28]
                            # orig_ip_header = struct.unpack(
                            #     '!BBHHHBBH4s4s', orig_ip_packet[:20])

                            # orig_ttl = self.original_datagrams.get(orig_datagram_port, None)
                            # if orig_ttl is not None:
                            #     if orig_ttl not in self.intermediate_ips_with_ttl:
                            #         self.intermediate_ips_with_ttl[orig_ttl] = set()
                            #     self.intermediate_ips_with_ttl[orig_ttl].add(intermediate_ip)

                            #     # OLD CODE
                            # orig_ttl = orig_ip_header[5]
                            # orig_ip_header = struct.unpack(
                            #     '!BBHHHBBH4s4s', orig_ip_packet)
                            # # Get source IP address from original IP header
                            # intermediate_ip = socket.inet_ntoa(
                            #     orig_ip_header[8])

                            # if intermediate_ip != self.source_node_ip and intermediate_ip != self.ultimate_destination_ip:
                            #     if ttl not in self.intermediate_ips_with_ttl:
                            #         self.intermediate_ips_with_ttl[ttl] = set()
                            #     self.intermediate_ips_with_ttl[ttl].add(
                            #         intermediate_ip)

                            if orig_ttl not in self.intermediate_ips_with_ttl:
                                self.intermediate_ips_with_ttl[orig_ttl] = set(
                                )
                            self.intermediate_ips_with_ttl[orig_ttl].add(
                                intermediate_ip)

        # Calculate and print RTT averages and standard deviations

        # for ip, rtt_list in self.rtt_data.items():
        #     if rtt_list:  # Ensure the list is not empty
        #         avg_rtt = sum(rtt_list) / len(rtt_list)
        #         std_dev_rtt = (
        #             sum((x - avg_rtt) ** 2 for x in rtt_list) / len(rtt_list)) ** 0.5
        #         # Now store the average and standard deviation in the dictionary, or print them
        #         self.rtt_data[ip] = {'avg': avg_rtt, 'std_dev': std_dev_rtt}
        #         print(
        #             f"Average RTT to {ip}: {avg_rtt}s, Standard deviation: {std_dev_rtt}s")
        #     else:
        #         # Handle the case where there are no RTTs recorded for this IP
        #         print(f"No RTT data for IP {ip}")

        # for ip, rtts_list in rtts.items():
        #     avg_rtt = sum(rtts_list) / len(rtts_list)
        #     std_dev_rtt = (
        #         sum((x - avg_rtt) ** 2 for x in rtts_list) / len(rtts_list)) ** 0.5
        #     print(f"Average RTT to {ip}: {avg_rtt}")
        #     print(f"RTT standard deviation to {ip}: {std_dev_rtt}")

        # Other processing or method calls (like RTT calculations) go here
            # Print the results'

            # Print the fragmentation and RTT results
        print(f"The IP address of the source node: {self.source_node_ip}")
        print(
            f"The IP address of the ultimate destination node: {self.ultimate_destination_ip}")
        print("The IP addresses of the intermediate nodes:")
        for ttl in sorted(self.intermediate_ips_with_ttl):
            for ip in self.intermediate_ips_with_ttl[ttl]:
                print(f"\t router {ttl}: {ip}")

        # for index, ip in enumarate(sorted(self.intermediate_ips), start=1):
        #     print(f"\trouter {index}: {ip}")

        print("\nThe values in protocol field of IP headers:")
        for protocol, name in self.protocol_values.items():
            print(f"\t{protocol}: {name}")

        print("Collected intermediate IPs:", self.intermediate_ips)

        # for ip, rtt_details in sorted(self.rtt_data.items()):
        #     print(
        #         f"The average RTT between {self.source_node_ip} and {ip} is: {rtt_details['avg']:.6f} ms, the s.d. is: {rtt_details['std_dev']:.6f} ms")

        return None

    # ... Any additional methods you might have ...

# Additional classes (like IP_Header) and methods (for RTT calculation, etc.) here
