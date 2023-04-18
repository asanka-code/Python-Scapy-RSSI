from scapy.all import *
#from scapy import rdpcap
from scapy.config import conf
conf.use_pcap = True

# Function to extract signal strength from RadioTap header
def get_signal_strength(packet):

    if packet.haslayer(Dot11):
        print("Dot11 layer available")
    else:
        print("Dot11 layer not available")


    if packet.haslayer(RadioTap):
        print("RadioTap available")
        # Extract signal strength (in dBm) from RadioTap header
        dbm_sig = packet.dBm_AntSignal
        # Convert signal strength to milliwatts
        mW_sig = 10 ** (dbm_sig / 10)
        return mW_sig
    else:
        print("RadioTap not available")
        return None

# Open a PCAP file containing Wi-Fi packets
#packets = rdpcap('data.pcap')

# Sniff some packets
#packets=sniff(count=50)
packets=sniff(iface="wlp3s0mon", count=10)

print(len(packets))

# Loop through each packet in the file and extract the signal strength
for packet in packets:
    print(len(packet))
    mW_sig = get_signal_strength(packet)
    if mW_sig is not None:
        print(f"Signal strength: {mW_sig:.2f} mW")
        #print("Signal strength: {mW_sig:.2f} mW")
