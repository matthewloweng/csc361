Instructions to use PCAP Analyzer:

Pre-requisites:

- Python 3.x
- Access to a terminal or command-line interface

Installation:
No installation is required, simply download the script files to a directory on your system

Usage and instructions:
In order to use the PCAP analyzer, navigate to the directory containing the script files in your terminal, and run the following command:

python3 main.py <path_to_pcap_file>

Replace `<path_to_pcap_file>` with the actual path to the `.pcap` file you want to analyze.

Output:
The program will display the following information:
- Connection details for each connection found in the `.pcap` file
- Total counts of complete, reset, and open connections
- Detailed statistics for complete TCP connections, including start time, end time, duration, packet counts, and more.