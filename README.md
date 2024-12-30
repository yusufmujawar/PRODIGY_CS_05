# PRODIGY_CS_05 #
Task: Network Packet Analyzer Application Date: 23-December-2024

*** WELCOME TO NETWORK PACKET ANALYZER APPLICATION ***

In the Network Packet Analyzer, we develop an application using Python programming. We utilize network packet and port libraries such as Scapy and Argparse, specifying layers like IP, TCP, and UDP. 
The main function is defined as the `packet_analysis` function, which processes each packet. This function first checks for the presence of the IP layer; if it exists, it extracts the source and destination IP addresses. It also determines the protocol used, converting it into a human-readable format. For TCP packets, the function examines the destination port to identify HTTP (port 80) or HTTPS (port 443) requests. For UDP packets, it checks if the destination port is 53, indicating a DNS request. Additionally, the function retrieves the source and destination MAC addresses of the packet.
Scapy is a powerful packet manipulation tool for computer networks, originally written in Python. It can forge or decode packets for a wide range of protocols, send them over the network, capture them, and match requests with replies.The script concludes with the `sniff` function from Scapy, which filters for IP packets and uses the `packet_analysis` function. This allows the application to continuously monitor and analyze network traffic in real time.

