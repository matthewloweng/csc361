import struct
import os
import sys
from packet_struct import IP_Header, TCP_Header, packet


class Connection:
    def __init__(self, src_ip, src_port, dest_ip, dest_port):
        # self.endpoints = sorted([(src_ip, src_port), (dest_ip, dest_port)])
        # self.src_ip, self.src_port = self.endpoints[0]
        # self.dest_ip, self.dest_port = self.endpoints[1]

        self.src_ip, self.src_port = src_ip, src_port
        self.dest_ip, self.dest_port = dest_ip, dest_port

        # self.src_port = src_port
        # self.dest_ip = dest_ip
        # self.dest_port = dest_port
        # Initialize RST state here
        self.states = {"SYN": 0, "FIN": 0, "RST": 0}
        self.start_time = 0
        self.end_time = 0
        self.packets = 0
        self.data_bytes = 0
        self.rtts = []       # List to store RTT values
        self.window_sizes = []  # List to store window sizes
        self.packets_src_to_dest = 0
        self.packets_dest_to_src = 0
        self.bytes_src_to_dest = 0
        self.bytes_dest_to_src = 0

    # to represent connection state in "s1f1" format
    def connection_state(self):
        syn_count = self.states["SYN"]
        fin_count = self.states["FIN"]
        rst_count = self.states["RST"]

        if rst_count > 0:
            return "R"
        else:
            return f"S{syn_count}F{fin_count}"

    def __repr__(self):
        duration = self.end_time - self.start_time
        return (f"SRC_IP={self.src_ip}, SRC_PORT={self.src_port}, DST_IP={self.dest_ip}, "
                f"DST_PORT={self.dest_port}, STATE={self.connection_state()}, PACKETS={self.packets}, "
                f"BYTES={self.data_bytes}, DURATION={duration:.6f}")

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dest_ip, self.dest_port))

    # def __eq__(self, other):
    #     return (self.src_ip, self.src_port, self.dest_ip, self.dest_port) == (other.src_ip, other.src_port, other.dest_ip, other.dest_port) or \
    #         (self.src_ip, self.src_port, self.dest_ip, self.dest_port) == (
    #             other.dest_ip, other.dest_port, other.src_ip, other.src_port)

    def __eq__(self, other):
        # Compare considering direction
        return (self.src_ip, self.src_port, self.dest_ip, self.dest_port) == \
            (other.src_ip, other.src_port, other.dest_ip, other.dest_port)


class PcapParser:
    def __init__(self, filename):
        self.filename = filename
        self.connections = {}
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

                        self._handle_tcp_packet(
                            ip_header_obj.src_ip, ip_header_obj.dst_ip,
                            tcp_header_obj.src_port, tcp_header_obj.dst_port,
                            tcp_header_obj.flags, timestamp, len(packet_data),
                            tcp_header_obj.data_offset,  # Pass the data offset
                            tcp_packet_data  # Pass the tcp_packet_data
                        )
        self._calculate_rtt_method_2()
        return self.connections

    def _handle_tcp_packet(self, src_ip, dest_ip, src_port, dest_port, tcp_flags, timestamp, length, data_offset, tcp_packet_data):
        con = Connection(src_ip, src_port, dest_ip, dest_port)
        if con not in self.connections:
            self.connections[con] = con

        connection = self.connections[con]

        # Access the flags from the dictionary
        ack_flag = tcp_flags["ACK"]
        syn_flag = tcp_flags["SYN"]
        fin_flag = tcp_flags["FIN"]
        rst_flag = tcp_flags["RST"]  # Add this line

        if syn_flag or (syn_flag and ack_flag):  # considering SYN+ACK as SYN
            connection.states["SYN"] += 1
        if fin_flag:
            connection.states["FIN"] += 1
        if rst_flag:  # handle reset state
            connection.states["RST"] += 1

        if connection.start_time == 0:
            connection.start_time = timestamp

        connection.end_time = timestamp
        connection.packets += 1

        tcp_header_len = data_offset
        connection.data_bytes += length - (14 + tcp_header_len)

        # Extract window size
        window_size = struct.unpack('>H', tcp_packet_data[14:16])[0]
        connection.window_sizes.append(window_size)

        # Assuming the presence of the SYN flag indicates the start of a TCP connection
        # And that the corresponding ACK is the response to this SYN
        # This is a simple way to compute RTT. It might not be accurate for all situations.
        if syn_flag and not ack_flag:
            connection.start_time = timestamp
        elif syn_flag and ack_flag and connection.start_time:
            rtt = timestamp - connection.start_time
            connection.rtts.append(rtt)

        if src_ip == connection.src_ip and src_port == connection.src_port:
            connection.packets_src_to_dest += 1
            connection.bytes_src_to_dest += length - (14 + tcp_header_len)
        else:
            connection.packets_dest_to_src += 1
            connection.bytes_dest_to_src += length - (14 + tcp_header_len)

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

    def _calculate_rtt_method_2(self):
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
        # Compute and print statistics
        all_window_sizes = [win for conn in self.connections.values()
                            for win in conn.window_sizes]
        all_rtts = [rtt for conn in self.connections.values()
                    for rtt in conn.rtts]

        print("\nStatistics:")
        print(
            f"Window Size: Min: {min(all_window_sizes)}, Mean: {sum(all_window_sizes)/len(all_window_sizes)}, Max: {max(all_window_sizes)}")
        print(
            f"RTT: Min: {min(all_rtts):.6f}, Mean: {sum(all_rtts)/len(all_rtts):.6f}, Max: {max(all_rtts):.6f}")

    def count_connections(self):
        complete_connections = sum(
            1 for conn in self.connections.values() if conn.states["FIN"] > 0)
        open_connections = len(self.connections) - complete_connections
        reset_connections = sum(
            1 for conn in self.connections.values() if conn.states["RST"] > 0)

        # Displaying the computed statistics for part C
        print("\nC) General")
        print(
            f"Total number of complete TCP connections: {complete_connections}")
        print(f"Number of reset TCP connections: {reset_connections}")
        print(
            f"Number of TCP connections that were still open when the trace capture ended: {open_connections}")

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2  # extract reset flag
        ack = (value & 16) >> 4
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

        print("\nD) Complete TCP connections:")
        print(
            f"Minimum time duration: {min(durations):.6f}\nMean time duration: {sum(durations)/len(durations):.6f}\nMaximum time duration: {max(durations):.6f}\n")
        print(
            f"Minimum RTT value: {min(all_rtts):.6f}\nMean RTT value: {sum(all_rtts)/len(all_rtts):.6f}\nMaximum RTT value: {max(all_rtts):.6f}\n")
        print(
            f"Minimum number of packets including both send/received: {min(packet_counts)}")
        print(f"Mean number of packets including both send/received:",
              "{:.4f}".format(sum(packet_counts)/len(packet_counts)))
        print(
            f"Maximum number of packets including both send/received: {max(packet_counts)}\n")
        print(f"Minimum receive window size including both send/received:",
              min(all_window_sizes), "bytes")
        print(
            f"Mean receive window size including both send/received:", "{:.6f}".format(sum(all_window_sizes)/len(all_window_sizes)), "bytes")
        print(
            f"Maximum receive window size including both send/received: {max(all_window_sizes)} bytes")


def analyze(filename):
    parser = PcapParser(filename)
    connections = parser.parse()

    # A) Total number of connections:
    print("A) Total number of connections:", len(connections))
    print("B) Connections' details:")

    for idx, (_, connection) in enumerate(connections.items(), 1):
        duration = connection.end_time - connection.start_time
        print("+++++++++++++++++++++++++++++++++")
        print(f"Connection {idx}:")
        print("Source Address:", connection.src_ip)
        print("Destination Address:", connection.dest_ip)
        print("Source Port:", connection.src_port)
        print("Destination Port:", connection.dest_port)
        print("Status:", connection.connection_state())
        # assuming S2F2 represents a complete connection
        # if connection.connection_state() in ["S2F2", "R"]:
        print("Start time:", "{:.6f}".format(connection.start_time))
        print("End Time:", "{:.6f}".format(connection.end_time))
        # print("End Time:", connection.end_time)
        print("Duration:", "{:.5f}".format(duration))
        print("Number of packets sent from Source to Destination:",
              connection.packets_src_to_dest)
        print("Number of packets sent from Destination to Source:",
              connection.packets_dest_to_src)
        print("Total number of packets:", connection.packets)
        print("Number of data bytes sent from Source to Destination:",
              connection.bytes_src_to_dest)
        print("Number of data bytes sent from Destination to Source:",
              connection.bytes_dest_to_src)
        print("Total number of data bytes:", connection.data_bytes)
        print("END")
    parser.count_connections()
    parser.compute_detailed_stats()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_analyzer.py <path_to_cap_file>")
        sys.exit(1)

    cap_file = sys.argv[1]
    analyze(cap_file)
