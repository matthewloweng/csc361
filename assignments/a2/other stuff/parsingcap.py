def parse_cap_file(file_path):
    # Constants
    ETHERNET_HEADER_LENGTH = 14  # 14 bytes
    IP_HEADER_LENGTH = 20  # Minimum length, without options

    # Extract Ethernet frame data
    def extract_ethernet_frame(data):
        dst_mac = ":".join("{:02x}".format(b) for b in data[:6])
        src_mac = ":".join("{:02x}".format(b) for b in data[6:12])
        eth_type = int.from_bytes(data[12:14], byteorder='big')
        return dst_mac, src_mac, eth_type

    # Extract IP header data
    def extract_ip_header(data):
        src_ip = ".".join(str(b) for b in data[12:16])
        dst_ip = ".".join(str(b) for b in data[16:20])
        return src_ip, dst_ip

    # Read the file
    with open(file_path, 'rb') as f:
        data = f.read()

    offset = 0
    while offset < len(data):
        dst_mac, src_mac, eth_type = extract_ethernet_frame(data[offset:])
        print(f"Ethernet Frame: {src_mac} -> {dst_mac} | Type: {eth_type:04x}")

        # If eth_type indicates IP (0x0800), parse IP header
        if eth_type == 0x0800:
            offset += ETHERNET_HEADER_LENGTH
            src_ip, dst_ip = extract_ip_header(data[offset:])
            print(f"IP Packet: {src_ip} -> {dst_ip}")
            offset += IP_HEADER_LENGTH
        else:
            # Move to the next Ethernet frame
            offset += ETHERNET_HEADER_LENGTH

        # For simplicity, assume each packet has a static size (this is NOT a valid assumption)
        offset += 1500  # Approximate length for standard Ethernet frames


if __name__ == "__main__":
    parse_cap_file('sample-capture-file.cap')
