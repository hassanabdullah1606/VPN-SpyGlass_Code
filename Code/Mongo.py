from scapy.all import *
from pymongo import MongoClient
import time

# MongoDB setup
mongo_uri = "mongodb+srv://habdullahbscs20seecs:1Zj4MxA3Sv44xzPJ@vpnspyglass.yg51vbe.mongodb.net/?retryWrites=true&w=majority&appName=VPNSpyGlass"
client = MongoClient(mongo_uri)
db = client['my_database']  # Database name
collection = db['network_traffic']  # Collection name

def packet_callback(packet):
    if IP in packet:
        timestamp = time.time()  # Get current timestamp
        packet_data = {
            'timestamp': timestamp,
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'packet_size': len(packet)
        }
        
        if TCP in packet:
            packet_data['source_port'] = packet[TCP].sport
            packet_data['destination_port'] = packet[TCP].dport
            packet_data['protocol'] = 'TCP'
            packet_data['Type'] = 'Hard'
        elif UDP in packet:
            packet_data['source_port'] = packet[UDP].sport
            packet_data['destination_port'] = packet[UDP].dport
            packet_data['protocol'] = 'UDP'
            packet_data['Type'] = 'Normal'

        collection.insert_one(packet_data)

# Infinite loop for continuous packet sniffing and saving to MongoDB
try:
    while True:
        sniff(iface="WiFi", prn=packet_callback)
except KeyboardInterrupt:
    print("Packet capturing stopped.")
