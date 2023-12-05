import dpkt
import re
import socket
import sys
from traceroute.fragment import DatagramFragment
from traceroute.ip_protocols import ip_protocol_map
from traceroute.packet import Packet
from traceroute.results_logger import print_results
from typing import Dict, List


def read_trace_file(filename: str) -> (str, str, List[str], Dict[int, str]):
    """
    Parses a trace file to extract information about the traceroute operation.
    Returns source IP, destination IP, intermediate IPs, and protocols.
    """
    with open(filename, "rb") as f:
        # Check file extension to determine file type (pcap or pcapng)
        if re.match(r"^.*\.(pcap)$", filename):
            pcap = dpkt.pcap.Reader(f)
        elif re.match(r"^.*\.(pcapng)$", filename):
            pcap = dpkt.pcapng.Reader(f)
        else:
            print("Failed to read pcap or pcapng. Exiting.")
            sys.exit()

        # Initialize variables for storing processed data
        protocols = {}  # Stores protocol numbers and their corresponding names
        packets = {}  # Stores Packet objects indexed by a unique key
        fragments = {}  # Stores DatagramFragment objects indexed by fragment ID
        fragment_ids = {}  # Maps a unique key to a fragment ID
        max_ttl = 0  # Tracks the maximum TTL (Time To Live) value seen
        source_node_ip_address = ""  # IP address of the traceroute source
        # IP address of the traceroute destination
        ultimate_destination_node_ip_address = ""
        intermediate_ip_addresses = []  # List of IP addresses of intermediate routers
        ttls = [0] * 1024  # Array to track TTL adjustments

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)  # Parse Ethernet frame
            ip = eth.data  # Extract IP packet from the Ethernet frame

            # Ignore non-IP packets
            if type(ip) is not dpkt.ip.IP:
                continue

            # Update the set of protocols seen in the trace
            protocols[ip.p] = ip_protocol_map.get(ip.p, "Unknown protocol")

            # Extract source and destination IP addresses from the IP packet
            source_ip_address = socket.inet_ntoa(ip.src)
            destination_ip_address = socket.inet_ntoa(ip.dst)

            # Identify the source and ultimate destination IP addresses of the traceroute
            if ip.ttl == max_ttl + 1 and is_valid(ip.data):
                max_ttl = ip.ttl
                if ip.ttl == 1:
                    source_node_ip_address = source_ip_address
                    ultimate_destination_node_ip_address = destination_ip_address

            # Processing IP packets that are part of the traceroute
            if (source_ip_address == source_node_ip_address and
                destination_ip_address == ultimate_destination_node_ip_address and
                    ip.ttl <= max_ttl + 1):

                # Handle IP fragmentation
                fragment_id = ip.id
                fragment_offset = 8 * (ip.off & dpkt.ip.IP_OFFMASK)
                if fragment_id not in fragments:
                    fragments[fragment_id] = DatagramFragment()
                if mf_flag_set(ip) or fragment_offset > 0:
                    fragments[fragment_id].count += 1
                    fragments[fragment_id].offset = fragment_offset
                fragments[fragment_id].send_times.append(ts)

                # Placeholder for intermediate IP addresses
                intermediate_ip_addresses.extend([""] * 5)

                # Determine a unique key for the Packet object
                key = -1
                if is_udp(ip.data):
                    key = ip.data.dport
                elif is_icmp(ip.data, 8):
                    key = ip.data["echo"].seq
                if key != -1:
                    fragment_ids[key] = fragment_id
                    packets[key] = Packet()
                    packets[key].ttl = ip.ttl
                    packets[key].ttl_adj = ttls[ip.ttl]
                    ttls[ip.ttl] += 1

            # Process ICMP packets that are responses in the traceroute
            elif destination_ip_address == source_node_ip_address and is_icmp(ip.data):
                icmp_type = ip.data.type
                if icmp_type in [0, 8]:
                    # Update packet timestamps and source IP for ICMP echo requests/responses
                    packets[ip.data.data.seq].timestamp = ts
                    packets[ip.data.data.seq].source_ip_address = source_ip_address
                    packets[ip.data.data.seq].fragment_id = fragment_ids[ip.data.data.seq]
                    continue

                # Extract packet data from ICMP messages
                packet_data = ip.data.data.data.data

                # Match ICMP messages to the corresponding traceroute packets
                if is_udp(packet_data):
                    key = packet_data.dport
                elif is_icmp(packet_data):
                    key = packet_data["echo"].seq

                    # Update packet information based on the extracted key.
                    if key in packets:
                        packets[key].timestamp = ts
                        packets[key].source_ip_address = source_ip_address
                        packets[key].fragment_id = fragment_ids[key]
                        # Store intermediate IP addresses for ICMP type 11 (Time Exceeded).
                        if icmp_type == 11 and source_ip_address not in set(intermediate_ip_addresses):
                            ttl = packets[key].ttl
                            ttl_adj = packets[key].ttl_adj
                            intermediate_ip_addresses[(
                                5 * ttl) - 1 + ttl_adj] = source_ip_address

        # Filter out empty intermediate IP addresses.
        intermediate_ip_addresses = [
            ip for ip in intermediate_ip_addresses if ip != ""]
        # Calculate round trip times for all packets.
        round_trip_times = compute_round_trip_times(
            packets.values(), fragments)

        return (source_node_ip_address,
                ultimate_destination_node_ip_address,
                intermediate_ip_addresses,
                protocols,
                fragments,
                round_trip_times)

    # ... Other function definitions (compute_round_trip_times, mf_flag_set, is_udp, is_icmp, is_valid) ...
