from scapy.all import *
import csv
import time

def packet_callback(packet):
    packet_info = {}
    
    if IP in packet:
        packet_info['Source IP'] = packet[IP].src
        packet_info['Destination IP'] = packet[IP].dst
        packet_info['Protocol'] = packet[IP].proto
        packet_info['Packet Size'] = len(packet)
    
        if TCP in packet:
            packet_info['Source Port'] = packet[TCP].sport
            packet_info['Destination Port'] = packet[TCP].dport
        elif UDP in packet:
            packet_info['Source Port'] = packet[UDP].sport
            packet_info['Destination Port'] = packet[UDP].dport
    
        with open('traffic_info.csv', 'a', newline='') as csvfile:
            fieldnames = ['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Packet Size']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow(packet_info)

# Start capturing network traffic for 10 seconds
start_time = time.time()
end_time = start_time + 10
while time.time() < end_time:
    sniff(iface="WiFi", prn=packet_callback, timeout=1)
