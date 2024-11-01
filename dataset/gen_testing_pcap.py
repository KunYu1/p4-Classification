from scapy.all import *
from collections import defaultdict
import numpy as np
import pandas as pd
import json
from os import listdir
from os.path import isfile, join
import os
import csv

with open('dict.json', 'r', encoding='utf-8') as json_file:
    dir_dict = json.load(json_file)
keys = list(dir_dict.values())

dataset_path = "./archive/Network-Traffic-Dataset/"

test_dataset_path ='./testing/'
os.makedirs(test_dataset_path, exist_ok=True)

test_csv = 'test_5tuple.csv'

def read_csv(csv_file):
    filter_conditions = []
    with open(csv_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            filter_conditions.append({
                'ip_src': row['ip_src'],
                'ip_dst': row['ip_dst'],
                'sport': int(row['sport']),
                'dport': int(row['dport']),
                'protocol': row['protocol']
            })
    return filter_conditions
conditions = read_csv(test_csv)

def match(session, conditions):
    for condition in conditions:
        if (session[0] == condition['ip_src'] and
            session[1] == condition['ip_dst'] and
            session[2] == condition['sport'] and
            session[3] == condition['dport'] and
            session[4] == condition['protocol']):
            return True
    return False

for folder_name in keys:
    folder_path = join(dataset_path, folder_name) 
    files = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]
    matched_packets = []
    for file in files:
        packets = rdpcap(join(folder_path, file))
        sessions = defaultdict(list)
        for pkt in packets:
            # Check whether the packet is TCP
            if pkt.haslayer('IP') and pkt.haslayer('TCP'):
                ip_src = pkt['IP'].src
                ip_dst = pkt['IP'].dst
                sport = pkt['TCP'].sport
                dport = pkt['TCP'].dport
                
                session_key = (ip_src, ip_dst, sport, dport, 'TCP')
                reverse_key = (ip_dst, ip_src, dport, sport, 'TCP')
                
                if reverse_key in sessions:
                    sessions[reverse_key].append((pkt, 'bwd'))  # backward
                else:
                    sessions[session_key].append((pkt, 'fwd'))  # forward
            elif pkt.haslayer('IP') and pkt.haslayer('UDP'):
                ip_src = pkt['IP'].src
                ip_dst = pkt['IP'].dst
                sport = pkt['UDP'].sport
                dport = pkt['UDP'].dport
                
                session_key = (ip_src, ip_dst, sport, dport, 'UDP')
                reverse_key = (ip_dst, ip_src, dport, sport, 'UDP')
                
                if reverse_key in sessions:
                    sessions[reverse_key].append((pkt, 'bwd'))  # backward
                else:
                    sessions[session_key].append((pkt, 'fwd'))  # forward
        
        for session, pkts in sessions.items():
            # Ignore sessions with fewer than 8 packets.
            if len(pkts) < 8 or not match(session, conditions):
                continue
            for match_pkt, match_dir in pkts:
                matched_packets.append(match_pkt)
        print(f"{join(folder_path, file)} Done~!")
    if matched_packets:
        wrpcap(join(test_dataset_path, f"{folder_name}.pcap"), matched_packets)
            

