import struct
import os
import sys

from packet_struct import IP_Header, TCP_Header, packet
from connection import Connection


def print_connection_details(connections):

    # A) Total number of connections:
    print("A) Total number of connections:", len(connections))
    print("________________________________________________\n")
    print("B) Connection's details\n")

    for idx, (_, connection) in enumerate(connections.items(), 1):
        duration = connection.end_time - connection.start_time
        if idx > 1:

            print("+++++++++++++++++++++++++++++++++")
        print(f"Connection {idx}:")
        print("Source Address:", connection.dest_ip)
        print("Destination Address:", connection.src_ip)
        print("Source Port:", connection.dest_port)
        print("Destination Port:", connection.src_port)
        print("Status:", connection.connection_state())
        if connection.connection_state() not in ["S1F0", "S2F0", "S3F0", "S1F0/R", "S2F0/R", "S3F0/R"]:

            print("Start time:", "{:.6f}".format(connection.start_time))
            print("End Time:", "{:.6f}".format(connection.end_time))
            print("Duration:", "{:.6f}".format(duration))
            print("Number of packets sent from Source to Destination:",
                  connection.packets_dest_to_src)
            print("Number of packets sent from Destination to Source:",
                  connection.packets_src_to_dest)
            print("Total number of packets:", connection.packets)
            print("Number of data bytes sent from Source to Destination:",
                  connection.bytes_dest_to_src)
            print("Number of data bytes sent from Destination to Source:",
                  connection.bytes_src_to_dest)
            print("Total number of data bytes:", connection.data_bytes)
            print("END")
    print("________________________________________________\n")


def print_statistics(all_window_sizes, all_rtts):
    print("\nStatistics:")
    print(
        f"Window Size: Min: {min(all_window_sizes)}, Mean: {sum(all_window_sizes)/len(all_window_sizes)}, Max: {max(all_window_sizes)}")
    print(
        f"RTT: Min: {min(all_rtts):.6f}, Mean: {sum(all_rtts)/len(all_rtts):.6f}, Max: {max(all_rtts):.6f}")


def print_connection_counts(complete_connections, reset_connections, open_connections):
    print("C) General\n")
    print(f"Total number of complete TCP connections: {complete_connections}")
    print(f"Number of reset TCP connections: {reset_connections}")
    print(
        f"Number of TCP connections that were still open when the trace capture ended: {open_connections}")
    print("________________________________________________")


def print_detailed_complete_tcp_statistics(durations, all_rtts, packet_counts, all_window_sizes):
    print("\nD) Complete TCP connections:\n")
    print(
        f"Minimum time duration: {min(durations):.6f} seconds\nMean time duration: {sum(durations)/len(durations):.6f} seconds\nMaximum time duration: {max(durations):.6f} seconds\n")
    print(
        f"Minimum RTT value: {min(all_rtts):.6f}\nMean RTT value: {sum(all_rtts)/len(all_rtts):.6f}\nMaximum RTT value: {max(all_rtts):.6f}\n")
    print(
        f"Minimum number of packets including both send/received: {min(packet_counts)}")
    print(
        f"Mean number of packets including both send/received: {sum(packet_counts)/len(packet_counts):.4f}")
    print(
        f"Maximum number of packets including both send/received: {max(packet_counts)}\n")
    print(
        f"Minimum receive window size including both send/received: {min(all_window_sizes)} bytes")
    print(
        f"Mean receive window size including both send/received: {sum(all_window_sizes)/len(all_window_sizes):.6f} bytes")
    print(
        f"Maximum receive window size including both send/received: {max(all_window_sizes)} bytes")
    print("________________________________________________")
