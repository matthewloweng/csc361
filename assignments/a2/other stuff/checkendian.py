import struct


def check_pcap_endianess(file_path):
    with open(file_path, 'rb') as f:
        # Read the first 4 bytes to get the magic number
        magic_number = f.read(4)
        if len(magic_number) < 4:
            raise ValueError("Invalid pcap file.")

        # Check the magic number
        if magic_number == b'\xa1\xb2\xc3\xd4':
            return 'little'
        elif magic_number == b'\xd4\xc3\xb2\xa1':
            return 'big'
        else:
            raise ValueError(
                "Unknown magic number: not a pcap file or not in expected formats.")


# Usage
file_path = 'sample-capture-file.cap'
endianess = check_pcap_endianess(file_path)
print(f"The pcap file is in {endianess} endian format.")
