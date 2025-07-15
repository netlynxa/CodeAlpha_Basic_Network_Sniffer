# CodeAlpha_Basic_Network_Sniffer
This repository contains the code for a basic Command Line Interface (CLI) Packet Sniffer developed during my Task 1 of my cybersecuirty CodeAlpha internship 

# Feautures 
- captures live network packets
- Displays source/destination IPs,Protocol types, and payloads
- Supports TCP,UDP,ICMP,IGMP Analysis
- Saves and analysis '.pcap' files
- Compares python CLI output vs Wireshark GUI

# Tools Used 
- Python 3
- Scapy
- Wireshark
- Kali LINUX

# How to Run  
# 1.Install Scapy 
bash 
sudo apt install python3-scapy

# 2.Run the Packet Sniffer 
 bash
 sudo python3 sniffer.py

# 3.Test it (In Another Terminal)
bash 
ping google.com

# 4.Optional.save
python analyze_pcap.py
 
# Result 
Succesfully Implemented a packet sniffer and verified output accuracy against Wireshark 




 
