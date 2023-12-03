class Connection:
    def __init__(self, src_ip, src_port, dest_ip, dest_port):
        self.endpoints = sorted([(src_ip, src_port), (dest_ip, dest_port)])
        self.src_ip, self.src_port = self.endpoints[0]
        self.dest_ip, self.dest_port = self.endpoints[1]
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

        self.complete = False
        self.status = [0, 0, 0]  # SYN, FIN, RST counts
        self.sent = []
        self.received = []
        self.bytes_src_to_dest = 0
        self.bytes_dest_to_src = 0
        self.window_list = []

    def connection_state(self):
        syn_count = self.states["SYN"]
        fin_count = self.states["FIN"]
        rst_count = self.states["RST"]

        if rst_count > 0:
            return f"S{syn_count}F{fin_count}/R"
        else:
            return f"S{syn_count}F{fin_count}"

    def __repr__(self):
        duration = self.end_time - self.start_time
        return (f"SRC_IP={self.src_ip}, SRC_PORT={self.src_port}, DST_IP={self.dest_ip}, "
                f"DST_PORT={self.dest_port}, STATE={self.connection_state()}, PACKETS={self.packets}, "
                f"BYTES={self.data_bytes}, DURATION={duration:.6f}")

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dest_ip, self.dest_port))

    def __eq__(self, other):
        # Compare considering direction
        return (self.src_ip, self.src_port, self.dest_ip, self.dest_port) == \
            (other.src_ip, other.src_port, other.dest_ip, other.dest_port)
