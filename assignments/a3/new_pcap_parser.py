import struct
from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection


class PcapParser:
    def __init__(self, filename, connections):
        self.connections = connections
        self.filename = filename
        self.byte_order = '<'  # Default to little endian
        self.start_timestamp = None
        self.ack_packets = []
        self.seq_packets = []
        self.source_node_ip = ""
        self.ultimate_destination_ip = ""
        self.intermediate_ips = set()

    def parse(self):
        with open(self.filename, 'rb') as f:
            global_header = f.read(24)
            magic_number = struct.unpack('I', global_header[:4])[0]

            if magic_number == 0xa1b2c3d4:
                self.byte_order = '<'  # Little endian
            elif magic_number == 0xd4c3b2a1:
                self.byte_order = '>'  # Big endian
            else:
                print("Unknown magic number in pcap file.")
                return None

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

                    if not self.source_node_ip:
                        self.source_node_ip = ip_header_obj.src_ip

                    if not self.ultimate_destination_ip:
                        self.ultimate_destination_ip = ip_header_obj.dst_ip

                    if ip_header_obj.src_ip != self.source_node_ip and ip_header_obj.src_ip != self.ultimate_destination_ip:
                        self.intermediate_ips.add(ip_header_obj.src_ip)

                    protocol = ip_packet[9]
                    if protocol == 6:  # TCP
                        ip_header_len = (ip_packet[0] & 0x0F) * 4
                        tcp_packet_data = ip_packet[ip_header_len:]
                        tcp_flags_byte = tcp_packet_data[13:14]
                        tcp_header_obj = TCP_Header()
                        tcp_header_obj.get_src_port(tcp_packet_data[0:2])
                        tcp_header_obj.get_dst_port(tcp_packet_data[2:4])
                        tcp_header_obj.get_flags(tcp_flags_byte)
                        tcp_header_obj.get_data_offset(
                            tcp_packet_data[12:13])  # Extract the data offset

                        self.handle_tcp_packet(
                            ip_header_obj.src_ip, ip_header_obj.dst_ip,
                            tcp_header_obj.src_port, tcp_header_obj.dst_port,
                            tcp_header_obj.flags, timestamp, len(packet_data),
                            tcp_header_obj.data_offset, tcp_packet_data, ip_header_len,
                            ip_packet
                        )
        self.calculate_rtt()
        return self.connections

    # ... Rest of your existing methods ...

    def calculate_rtt(self):
        # ... Your existing RTT calculation logic ...
        pass

    def compute_stats(self):
        # ... Your existing stats computation logic ...
        pass

    # ... Any additional methods you might have ...
