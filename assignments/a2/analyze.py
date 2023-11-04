from pcap_parser import PcapParser
from print_output import print_connection_details


def analyze_pcap_connections(connections):
    # connections = {}

    # parser = PcapParser(filename, connections)
    # connections = parser.parse()
    # parser.parse()

    # A) Total number of connections:

    print_connection_details(connections)

    # print("A) Total number of connections:", len(connections))
    # print("B) Connections' details:")

    # for idx, (_, connection) in enumerate(connections.items(), 1):
    #     duration = connection.end_time - connection.start_time
    #     print("+++++++++++++++++++++++++++++++++")
    #     print(f"Connection {idx}:")
    #     # IDK HOW TO SWAP SO SWAPPING VALUES
    #     print("Source Address:", connection.dest_ip)
    #     # ONCE AGAIN IDK HOW TO SWAP
    #     print("Destination Address:", connection.src_ip)
    #     print("Source Port:", connection.dest_port)
    #     print("Destination Port:", connection.src_port)
    #     print("Status:", connection.connection_state())
    #     # assuming S2F2 represents a complete connection
    #     # if connection.connection_state() in ["S2F2", "R"]:
    #     print("Start time:", "{:.6f}".format(connection.start_time))
    #     print("End Time:", "{:.6f}".format(connection.end_time))
    #     # print("End Time:", connection.end_time)
    #     print("Duration:", "{:.5f}".format(duration))
    #     print("Number of packets sent from Source to Destination:",
    #           connection.packets_dest_to_src)  # CHANGING
    #     print("Number of packets sent from Destination to Source:",
    #           connection.packets_src_to_dest)  # CHANGING IDK WHY IT WORKS LIKE THIS!!!
    #     print("Total number of packets:", connection.packets)
    #     print("Number of data bytes sent from Source to Destination:",
    #           connection.bytes_dest_to_src)
    #     print("Number of data bytes sent from Destination to Source:",
    #           connection.bytes_src_to_dest)
    #     print("Total number of data bytes:", connection.data_bytes)
    #     print("END")

    # parser.count_connections()
    # parser.compute_detailed_stats()
