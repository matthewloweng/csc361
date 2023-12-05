import struct


class GlobalHeader:

    magic_num = None
    version_min = None
    version_maj = None
    this_zone = None
    sig_figs = None
    snap_len = None
    network_type = None

    def __init__(self, buffer):
        self.magic_numb, self.version_min, self.version_maj, self.this_zone, self.sig_figs, self.snap_len, self.network_type = struct.unpack(
            'IHHiIII', buffer)


class UDPHeader:

    src_port = None
    dst_port = None
    udp_length = None
    checksum = None

    def set_src_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_dst_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_udp_len(self, buffer):
        result = struct.unpack('BB', buffer)
        self.udp_length = int(
            str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_checksum(self, buffer):
        result = struct.unpack('BB', buffer)
        self.checksum = str(hex(result[0])) + str(hex(result[1]))


class ICMPHeader:

    type_num = None
    code = None
    src_port = None
    dst_port = None
    sequence = None

    def set_type(self, buffer):
        result = struct.unpack('B', buffer)[0]
        self.type_num = int(result)

    def set_code(self, buffer):
        result = struct.unpack('B', buffer)[0]
        self.code = int(result)

    def set_src_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.src_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_dst_port(self, buffer):
        result = struct.unpack('BB', buffer)
        self.dst_port = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_sequence(self, buffer):
        result = struct.unpack('BB', buffer)
        self.sequence = int(str(hex(result[0])) + str(hex(result[1]))[2:], 16)


class IP_Header:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    total_length = None
    id = None
    flags = None
    fragment_offset = None
    ttl = None
    protocol = None

    # def __init__(self):
    #     self.src_ip = None
    #     self.dst_ip = None
    #     self.ip_header_len = 0
    #     self.total_len = 0

    def set_ip_header_len(self, value):
        result = struct.unpack('B', value)[0]
        self.ip_header_len = (result & 15) * 4

    def set_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        self.total_length = num1 + num2 + num3 + num4

    def set_ip(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        self.src_ip = str(src_addr[0]) + '.' + str(src_addr[1]) + \
            '.' + str(src_addr[2]) + '.' + str(src_addr[3])
        self.dst_ip = str(dst_addr[0]) + '.' + str(dst_addr[1]) + \
            '.' + str(dst_addr[2]) + '.' + str(dst_addr[3])

    def set_id(self, buffer):
        result = struct.unpack('BB', buffer)
        self.id = int(
            str(hex(result[0])) + str(hex(result[1]))[2:], 16)

    def set_fragment_offset(self, buffer):
        num0 = hex(((buffer[0] & 224) >> 5))
        num1 = ((buffer[0] & 16) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        self.flags = num0
        self.fragment_offset = (num1 + num2 + num3 + num4) * 8

    def set_ttl(self, buffer):
        self.ttl = struct.unpack('B', buffer)[0]

    def set_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack('BBBB', buffer1)
        dst_addr = struct.unpack('BBBB', buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.' + \
            str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.' + \
            str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        length = num1+num2+num3+num4
        self.total_len_set(length)


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        # print(self.src_port)
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4)*16*16*16
        num2 = (buffer[0] & 15)*16*16
        num3 = ((buffer[1] & 240) >> 4)*16
        num4 = (buffer[1] & 15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        # print(self.dst_port)
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        # print(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack('>I', buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H', buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4)*4
        self.data_offset_set(length)
        # print(self.data_offset)
        return None

    def relative_seq_num(self, orig_num):
        if (self.seq_num >= orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        # print(self.seq_num)

    def relative_ack_num(self, orig_num):
        if (self.ack_num >= orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)


class new_packet():

    # pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    icmp = None
    udp = None
    data = None
    payload = None
    IP_header = None
    header = None
    # Header
    ts_sec = None
    ts_usec = None
    incl_len = None
    orig_len = None
    # Global Header

    # UDP Header

    # ICMP Header

    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        # self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        # self.header = PacketHeader()
        # self.ipv4 = IPV4Header()
        self.icmp = ICMPHeader()
        self.udp = UDPHeader()
        self.data = b''
        self.payload = 0
        self.timestamp = 0

    def timestamp_set(self, buffer1, buffer2, orig_time):
        seconds = struct.unpack('I', buffer1)[0]
        microseconds = struct.unpack('<I', buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time, 6)
        # print(self.timestamp,self.packet_No)

    def set_timestamp(self, orig_time):
        seconds = self.ts_sec
        microseconds = self.ts_usec
        self.timestamp = 1000 * \
            round(seconds + microseconds * 0.000000001 - orig_time, 6)

    def packet_No_set(self, number):
        self.packet_No = number
        # print(self.packet_No)

    def get_RTT_value(self, p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt, 8)

    def set_header(self, buffer):
        self.set_header(buffer)

    def set_data(self, buffer):
        self.data = buffer

    def set_number(self, value):
        self.number = value

    def set_rtt(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)

    def set_ip_header(self):
        offset = 14  # ethernet header length
        self.IP_header.set_ip_header_len(self.data[offset+0: offset+1])
        self.IP_header.set_total_len(self.data[offset+2: offset+4])
        self.IP_header.set_id(self.data[offset+4: offset+6])
        self.IP_header.set_fragment_offset(self.data[offset+6: offset+8])
        self.IP_header.set_ttl(self.data[offset+8: offset+9])
        self.IP_header.set_protocol(self.data[offset+9: offset+10])
        self.IP_header.set_ip(self.data[offset+12: offset+16],
                              self.data[offset+16: offset+20])

    def set_icmp(self):
        offset = 14 + self.IP_header.ip_header_len
        self.icmp.set_type(self.data[offset+0: offset+1])
        self.icmp.set_code(self.data[offset+1: offset+2])
        # windows
        if self.icmp.type_num == 8 or self.icmp.type_num == 0:
            self.icmp.set_sequence(self.data[offset+6: offset+8])
        # linux
        offset += 8 + self.IP_header.ip_header_len
        if offset+4 <= self.incl_len:
            if self.icmp.type_num != 8 and self.icmp.type_num != 0:
                self.icmp.set_sequence(
                    self.data[offset+6: offset+8])  # also windows
            self.icmp.set_src_port(self.data[offset+0: offset+2])
            self.icmp.set_dst_port(self.data[offset+2: offset+4])
        else:
            self.icmp.src_port = 0
            self.icmp.dst_port = 0

    def set_udp(self):
        offset = 14 + self.IP_header.ip_header_len
        self.udp.set_src_port(self.data[offset+0: offset+2])
        self.udp.set_dst_port(self.data[offset+2: offset+4])
        self.udp.set_udp_len(self.data[offset+4: offset+6])
        self.udp.set_checksum(self.data[offset+6: offset+8])

    def set_header(self, buffer):
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack(
            'IIII', buffer)
