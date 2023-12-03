import struct
from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection
# from print_output import print_statistics, print_connection_counts, print_detailed_complete_tcp_statistics


class PcapParser:
    def __init__(self, filename, connections):
        self.connections = connections
        self.filename = filename
        self.byte_order = '<'  # Default to little endian
        self.start_timestamp = None
        self.ack_packets = []
        self.seq_packets = []

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
                            tcp_header_obj.data_offset,  # Pass the data offset
                            tcp_packet_data,  # Pass the tcp_packet_data
                            ip_header_len,
                            ip_packet
                        )
        self.calculate_rtt_method_2()
        return self.connections

    def calculate_payload_bytes(self, total_packet_length, ip_header_length, tcp_header_length):
        ethernet_header_length = 14
        payload_size = total_packet_length - \
            (ethernet_header_length + ip_header_length + tcp_header_length)
        return payload_size

    def handle_tcp_packet(self, src_ip, dest_ip, src_port, dest_port, tcp_flags, timestamp, length, data_offset, tcp_packet_data, ip_header_len, ip_packet):
        con = Connection(src_ip, src_port, dest_ip, dest_port)
        if con not in self.connections:
            self.connections[con] = con

        connection = self.connections[con]

        # Access the flags from the dictionary
        ack_flag = tcp_flags["ACK"]
        syn_flag = tcp_flags["SYN"]
        fin_flag = tcp_flags["FIN"]
        rst_flag = tcp_flags["RST"]

        # Adjust the start time based on the SYN flag
        # considering SYN without ACK as the start
        if syn_flag and not ack_flag and connection.states["SYN"] == 0:
            connection.start_time = timestamp
            connection.states["SYN"] += 1
        elif syn_flag and ack_flag:
            connection.states["SYN"] += 1

        # Adjust the end time based on the FIN flag
        if fin_flag:
            connection.end_time = timestamp
            connection.states["FIN"] += 1
            connection.complete = True

        if rst_flag:  # handle reset state
            connection.states["RST"] += 1

            # OLD CODE BELOW, NEW CODE ABOVE

        # if syn_flag or (syn_flag and ack_flag):  # considering SYN+ACK as SYN
        #     connection.states["SYN"] += 1
        # if fin_flag:
        #     connection.states["FIN"] += 1
        # if rst_flag:  # handle reset state
        #     connection.states["RST"] += 1

        # if connection.start_time == 0:
        #     connection.start_time = timestamp

        # connection.end_time = timestamp
        connection.packets += 1

        tcp_header_len = data_offset
        connection.data_bytes += length - (14 + tcp_header_len)

        ip_header_len = (ip_packet[0] & 0x0F) * 4

        payload_length = self.calculate_payload_bytes(
            length, ip_header_len, tcp_header_len)

        if src_ip == connection.src_ip and src_port == connection.src_port:
            connection.packets_src_to_dest += 1
            connection.bytes_src_to_dest += payload_length
        else:
            connection.packets_dest_to_src += 1
            connection.bytes_dest_to_src += payload_length

        # Extract window size
        window_size = struct.unpack('>H', tcp_packet_data[14:16])[0]
        connection.window_sizes.append(window_size)

        if syn_flag and not ack_flag:
            connection.start_time = timestamp
        elif syn_flag and ack_flag and connection.start_time:
            rtt = timestamp - connection.start_time
            connection.rtts.append(rtt)

        # REMEMBER

        # if src_ip == connection.src_ip and src_port == connection.src_port:
        #     connection.packets_src_to_dest += 1
        #     connection.bytes_src_to_dest += length - (14 + tcp_header_len)
        # else:
        #     connection.packets_dest_to_src += 1
        #     connection.bytes_dest_to_src += length - (14 + tcp_header_len)

        ack_number = struct.unpack('>I', tcp_packet_data[8:12])[0]
        seq_number = struct.unpack('>I', tcp_packet_data[4:8])[0]

        self.ack_packets.append({
            'ack_number': ack_number,
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
        })

        self.seq_packets.append({
            'seq_number': seq_number,
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
        })

    def calculate_rtt_method_2(self):
        for ack_packet in reversed(self.ack_packets):
            same_ack_packets = [pkt for pkt in self.ack_packets if pkt['ack_number'] == ack_packet['ack_number'] and pkt['src_ip'] == ack_packet['src_ip']
                                and pkt['src_port'] == ack_packet['src_port'] and pkt['dest_ip'] == ack_packet['dest_ip'] and pkt['dest_port'] == ack_packet['dest_port']]

            if len(same_ack_packets) > 1:
                continue

            # Find first data packet with smaller seq number
            for seq_packet in reversed(self.seq_packets):
                if seq_packet['seq_number'] < ack_packet['ack_number'] and seq_packet['src_ip'] == ack_packet['dest_ip'] and seq_packet['src_port'] == ack_packet['dest_port'] and seq_packet['dest_ip'] == ack_packet['src_ip'] and seq_packet['dest_port'] == ack_packet['src_port']:
                    rtt = ack_packet['timestamp'] - seq_packet['timestamp']
                    conn = Connection(
                        seq_packet['src_ip'], seq_packet['src_port'], seq_packet['dest_ip'], seq_packet['dest_port'])
                    if conn in self.connections:
                        self.connections[conn].rtts.append(rtt)
                    break

    def compute_stats(self):
        all_window_sizes = [win for conn in self.connections.values()
                            for win in conn.window_sizes]
        all_rtts = [rtt for conn in self.connections.values()
                    for rtt in conn.rtts]
        # returning since printing elsewhere
        return all_window_sizes, all_rtts

    def count_connections(self):
        complete_connections = sum(
            1 for conn in self.connections.values() if conn.states["FIN"] > 0)
        open_connections = len(self.connections) - complete_connections
        reset_connections = sum(
            1 for conn in self.connections.values() if conn.states["RST"] > 0)

        return complete_connections, reset_connections, open_connections

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1  # extract syn flag
        rst = (value & 4) >> 2  # extract reset flag
        ack = (value & 16) >> 4  # extract ack flag
        self.flags_set(ack, rst, syn, fin)
        return None

    def compute_detailed_stats(self):
        complete_conns = [conn for conn in self.connections.values(
        ) if conn.connection_state() in ["S2F2", "R"]]

        # Time durations
        durations = [conn.end_time -
                     conn.start_time for conn in complete_conns]

        # RTT values
        all_rtts = [rtt for conn in complete_conns for rtt in conn.rtts]

        # Number of packets
        packet_counts = [conn.packets for conn in complete_conns]

        # Window sizes
        all_window_sizes = [
            win for conn in complete_conns for win in conn.window_sizes]

        return durations, all_rtts, packet_counts, all_window_sizes
