from scapy.all import *
from pymongo import MongoClient
import datetime
from pymongo import InsertOne 

# MongoDB setup
mongo_uri = "mongodb+srv://habdullahbscs20seecs:1Zj4MxA3Sv44xzPJ@vpnspyglass.yg51vbe.mongodb.net/?retryWrites=true&w=majority&appName=VPNSpyGlass"
client = MongoClient(mongo_uri)
db = client['my_database']  # Database name
collection = db['network_traffic']  # Collection name

# Get last N entries
N = 10  # Number of entries to retrieve
last_entries = collection.find().sort([('_id', -1)]).limit(N)

# Print the last entries
for entry in last_entries:
    print(entry)