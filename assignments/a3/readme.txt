README
------

This program analyzes a trace of IP datagrams created by the traceroute program. It provides information about the source and destination IP addresses, intermediate nodes, protocol values, the number of fragments, and RTT calculations.

Requirements:
- Python 3.x
- pcap file for analysis

Files:
- main.py: This is the main script that you should run with Python.
- final_pcap_parser.py: Contains the PcapParser class for parsing the pcap file.
- print_output.py: Contains the function to print the parsing results.
- packet_struct.py: Contains the classes for different packet headers.

How to run the program:
1. Ensure you have Python 3.x installed on your system.
2. Place the pcap file you want to analyze in the same directory as the scripts or provide the correct path to it.
3. Open a terminal or command prompt.
4. Navigate to the directory containing the program files.
5. Execute the script by running the following command:

   python3 main.py <path_to_pcap_file>

   Replace <path_to_pcap_file> with the actual path to the pcap file you wish to analyze.

Example:
python3 main.py group1-trace1.pcap

Output:

The IP address of the source node: 192.168.100.17
The IP address of ultimate destination node: 8.8.8.8
Length of intermediate_ips: 17
The IP addresses of the intermediate nodes:
         router 1: 142.104.68.167
         router 2: 142.104.68.1
         router 3: 192.168.9.5
         router 4: 192.168.10.1
         router 5: 192.168.8.6
         router 6: 142.104.252.37
         router 7: 142.104.252.246
         router 8: 207.23.244.242
         router 9: 206.12.3.17
         router 10: 199.212.24.64
         router 11: 206.81.80.17
         router 12: 74.125.37.91
         router 13: 72.14.237.123
         router 14: 209.85.249.155
         router 15: 209.85.250.121
         router 16: 209.85.249.153

The values in protocol field of IP headers:
        17: UDP
        1: ICMP

The number of fragments created from the original datagram is: 1

The offset of the last fragment is: 0


The avg RTT between 192.168.100.17 and 142.104.68.167 is: 11.366667 ms, the s.d. is: 0.206988 ms
The avg RTT between 192.168.100.17 and 142.104.68.1 is: 16.850667 ms, the s.d. is: 0.200051 ms
The avg RTT between 192.168.100.17 and 192.168.9.5 is: 16.008667 ms, the s.d. is: 0.22545 ms
The avg RTT between 192.168.100.17 and 192.168.10.1 is: 17.562 ms, the s.d. is: 0.206167 ms
The avg RTT between 192.168.100.17 and 192.168.8.6 is: 18.361 ms, the s.d. is: 0.230465 ms
The avg RTT between 192.168.100.17 and 142.104.252.37 is: 11.861333 ms, the s.d. is: 6.499943 ms
The avg RTT between 192.168.100.17 and 142.104.252.246 is: 13.507333 ms, the s.d. is: 0.329015 ms
The avg RTT between 192.168.100.17 and 207.23.244.242 is: 14.095667 ms, the s.d. is: 0.318757 ms
The avg RTT between 192.168.100.17 and 206.12.3.17 is: 18.234333 ms, the s.d. is: 0.235075 ms
The avg RTT between 192.168.100.17 and 199.212.24.64 is: 16.911667 ms, the s.d. is: 0.213561 ms
The avg RTT between 192.168.100.17 and 206.81.80.17 is: 19.429 ms, the s.d. is: 0.232151 ms
The avg RTT between 192.168.100.17 and 74.125.37.91 is: 11.77 ms, the s.d. is: 2.409 ms
The avg RTT between 192.168.100.17 and 72.14.237.123 is: 17.624 ms, the s.d. is: 0.0 ms
The avg RTT between 192.168.100.17 and 209.85.249.155 is: 19.821 ms, the s.d. is: 0.0 ms
The avg RTT between 192.168.100.17 and 209.85.250.121 is: 18.468 ms, the s.d. is: 0.0 ms
The avg RTT between 192.168.100.17 and 209.85.249.153 is: 20.572 ms, the s.d. is: 0.0 ms
The avg RTT between 192.168.100.17 and 8.8.8.8 is: 19.979923 ms, the s.d. is: 3.501104 ms

The program will output the analysis results to the console. Ensure that all related scripts are in the same directory for the program to run correctly.
