print()
print('***** Welcome to Network Packet Analyzer Application *****')
print('          *** Build By Mohamed Yusuf Mujawar ***          ')
print()

# Scapy is a packet manipulation tool for computer networks, originally written in Python. 
# It is capable of forging or decoding packets of a wide number of protocols, sending them on the wire, capturing them, and matching requests and replies.
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def packet_analysis(packet):
    # User can specify the packet in the IP layer
    if packet.haslayer(IP):
        # User can get Source IP
        source_ip = packet[IP].src
        #cUser can get Destination IP
        destination_ip = packet[IP].dst

        # Get protocol
        protocol = packet[IP].proto
        
        # User can get the protocol name
        if protocol == 6:
            protocol = "TCP"
        elif protocol == 17:
            protocol = "UDP"
        else:
            protocol = "Other"
        
        # User can get the website name
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80:
                print("HTTP Request")
            elif packet[TCP].dport == 443:
                print("HTTPS Request")
            else:
                print("Other Request")
            
        # User can get the website name
        if packet.haslayer(UDP):
            if packet[UDP].dport == 53:
                print("DNS Request")
            else:
                print("Other Request")
        
        # User can get the MAC address of the source
        source_mac = packet.src
        # User can get the MAC address of the destination
        destination_mac = packet.dst

        # Check the Raw layer to see if the packet contains any payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = ""  
        # Set payload to an empty string if not present

        # Print the All the details of the packet source IP, destination IP, protocol, and payload if present
        print("Netork Packet Details")
        print("--------------------------------")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print(f"Source MAC: {source_mac}")
        print(f"Destination MAC: {destination_mac}")
        print("--------------------------------")

# Start sniffing
sniff(filter="ip", prn=packet_analysis)