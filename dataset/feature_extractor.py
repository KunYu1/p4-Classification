from scapy.all import rdpcap
from collections import defaultdict
import numpy as np
import pandas as pd
import json
from os import listdir
from os.path import isfile, join
import os
with open('dict.json', 'r', encoding='utf-8') as json_file:
    dir_dict = json.load(json_file)
keys = list(dir_dict.values())
# 用於存放每個TCP session的封包數據
dataset_path = "./archive/Network-Traffic-Dataset/"
file_path_pv = "statistics_pv.csv"
file_path_ss = "statistics_ss.csv"
file_path_5tuple = "statistics_5tuple.csv"
for folder_name in keys:
    folder_path = join(dataset_path, folder_name) 
    files = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]
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

        # Helper function to extract the first packet's size and TTL
        def extract_first_packet_stats(packets):
            if packets:
                first_pkt = packets[0]
                pkt_len = first_pkt['IP'].len
                pkt_ttl = first_pkt['IP'].ttl
                return pkt_len, pkt_ttl
            return 0, 0

        packet_stats = []
        session_stats = []
        packet_5tuple_stats = []
        for session, pkts in sessions.items():
            # Ignore sessions with fewer than 8 packets.
            if len(pkts) < 8:
                continue
            # Initialization
            pkt_fwd_length_pre = 0
            pkt_bwd_length_pre = 0
            pkt_fwd_length_total = 0
            pkt_bwd_length_total = 0
            pkt_fwd_length_var = 0
            pkt_bwd_length_var = 0
            pkt_fwd_length_min = 0
            pkt_bwd_length_min = 0
            pkt_fwd_length_max = 0
            pkt_bwd_length_max = 0
            first_fwd = False
            first_bwd = False

            pkt_fwd_ttl_pre = 0
            pkt_bwd_ttl_pre = 0
            pkt_fwd_ttl_total = 0
            pkt_bwd_ttl_total = 0
            pkt_fwd_ttl_var = 0
            pkt_bwd_ttl_var = 0
            pkt_fwd_ttl_min = 0
            pkt_bwd_ttl_min = 0
            pkt_fwd_ttl_max = 0
            pkt_bwd_ttl_max = 0

            pkt_fwd_iat_pre = 0
            pkt_bwd_iat_pre = 0
            pkt_fwd_iat_total = 0
            pkt_bwd_iat_total = 0
            pkt_fwd_iat_var = 0
            pkt_bwd_iat_var = 0
            pkt_fwd_iat_min = 0
            pkt_bwd_iat_min = 0
            pkt_fwd_iat_max = 0
            pkt_bwd_iat_max = 0
            pkt_info = {}
            session_info = {}
            pkt_5tuple_info = {}
            pkt_5tuple_info['ip_src'] = session[0]
            pkt_5tuple_info['ip_dst'] = session[1]
            pkt_5tuple_info['sport'] = session[2]
            pkt_5tuple_info['dport'] = session[3]
            pkt_5tuple_info['protocol'] = session[4]
            session_info["pktTotalSize"] = 0
            session_info["pktMeanSize"] = 0
            session_info["pktVarSize"] = 0
            session_info["pktMinSize"] = 65535
            if pkts[0][0].haslayer('TCP'):
                session_info["serviceType"] = pkts[0][0]['TCP'].dport
            else:
                session_info["serviceType"] = pkts[0][0]['UDP'].dport
            session_info["windowTotal"] = 0
            session_info["windowMean"] = 0
            session_info["windowVar"] = 0
            session_info["windowMin"] = 65535
            session_info["windowMax"] = 0
            session_info["numberOfRstFlag"] = 0
            session_info["numberOfPshFlag"] = 0
            session_info["numberOfKeepAlive"] = 0
            session_info["numberOfSyncFlood"] = 0
            pkt_pre_length = 0
            pre_window = 0
            pre_flag = 0
            pkt_time = 0
            for i in range(0, 8):
                
                pkt_now = pkts[i][0]
                dir = pkts[i][1]
                
                pkt_now_length = pkt_now['IP'].len
                # session
                session_info["pktTotalSize"] += pkt_now_length
                session_info["pktMinSize"] = pkt_now_length if pkt_now_length < session_info["pktMinSize"] else session_info["pktMinSize"]
                session_info["pktVarSize"] += abs(pkt_now_length - pkt_pre_length) if i != 0 else 0
                pkt_pre_length = pkt_now_length
                
                if pkts[0][0].haslayer('TCP'):
                    flag = pkt_now['TCP'].flags
                    session_info["numberOfRstFlag"] += 1 if flag & 0x04 else 0  
                    session_info["numberOfPshFlag"] += 1 if flag & 0x08 else 0 
                    # TCP Packet without SYN, FIN, RST flag
                    if (flag & (0x02 | 0x01 | 0x04)) == 0:
                        session_info["numberOfKeepAlive"] += 1 if (flag & 0x08) and () else 0 
                    # Continuous syn packet
                    if flag & 0x02 and not (flag & 0x10) and pre_flag & 0x02 and not (pre_flag & 0x10) :
                        session_info["numberOfSyncFlood"] += 1 if flag & 0x08 else 0 
                    pre_flag = flag
                    window_size = pkt_now['TCP'].window
                else:
                    window_size = 0
                session_info["windowTotal"] += window_size
                session_info["windowMin"] = window_size if window_size < session_info["windowMin"] else session_info["windowMin"]
                session_info["windowMax"] = window_size if window_size > session_info["windowMax"] else session_info["windowMax"]
                session_info["windowVar"] += abs(pre_window - window_size) if i != 0 else 0
                pre_window = window_size

                pkt_fwd_length = pkt_now_length if dir == 'fwd' else pkt_fwd_length_pre
                pkt_bwd_length = pkt_now_length if dir == 'bwd' else pkt_bwd_length_pre
                pkt_fwd_length_total += pkt_now_length if dir == 'fwd' else 0
                pkt_bwd_length_total += pkt_now_length if dir == 'bwd' else 0
                pkt_fwd_length_var = abs(pkt_fwd_length_pre - pkt_now_length) if (dir == 'fwd' and first_fwd) else pkt_fwd_length_var
                pkt_bwd_length_var = abs(pkt_bwd_length_pre - pkt_now_length) if (dir == 'bwd' and first_bwd) else pkt_bwd_length_var
                pkt_fwd_length_min = pkt_now_length if((not first_fwd or pkt_fwd_length_min > pkt_now_length) and dir == 'fwd') else pkt_fwd_length_min
                pkt_bwd_length_min = pkt_now_length if((not first_bwd or pkt_bwd_length_min > pkt_now_length) and dir == 'bwd') else pkt_bwd_length_min
                pkt_fwd_length_max = pkt_now_length if((not first_fwd or pkt_fwd_length_max < pkt_now_length) and dir == 'fwd') else pkt_fwd_length_max
                pkt_bwd_length_max = pkt_now_length if((not first_bwd or pkt_bwd_length_max < pkt_now_length) and dir == 'bwd') else pkt_bwd_length_max
                pkt_fwd_length_pre = pkt_now_length if dir == 'fwd' else pkt_fwd_length_pre
                pkt_bwd_length_pre = pkt_now_length if dir == 'bwd' else pkt_bwd_length_pre

                pkt_now_ttl = pkt_now['IP'].ttl
                pkt_fwd_ttl = pkt_now_ttl if dir == 'fwd' else pkt_fwd_ttl_pre
                pkt_bwd_ttl = pkt_now_ttl if dir == 'bwd' else pkt_bwd_ttl_pre
                pkt_fwd_ttl_total += pkt_now_ttl if dir == 'fwd' else 0
                pkt_bwd_ttl_total += pkt_now_ttl if dir == 'bwd' else 0
                pkt_fwd_ttl_var = abs(pkt_fwd_ttl_pre - pkt_now_ttl) if (dir == 'fwd' and first_fwd) else pkt_fwd_ttl_var
                pkt_bwd_ttl_var = abs(pkt_bwd_ttl_pre - pkt_now_ttl) if (dir == 'bwd' and first_bwd) else pkt_bwd_ttl_var
                pkt_fwd_ttl_min = pkt_now_ttl if((not first_fwd or pkt_fwd_ttl_min > pkt_now_ttl) and dir == 'fwd') else pkt_fwd_ttl_min
                pkt_bwd_ttl_min = pkt_now_ttl if((not first_bwd or pkt_bwd_ttl_min > pkt_now_ttl) and dir == 'bwd') else pkt_bwd_ttl_min
                pkt_fwd_ttl_max = pkt_now_ttl if((not first_fwd or pkt_fwd_ttl_max < pkt_now_ttl) and dir == 'fwd') else pkt_fwd_ttl_max
                pkt_bwd_ttl_max = pkt_now_ttl if((not first_bwd or pkt_bwd_ttl_max < pkt_now_ttl) and dir == 'bwd') else pkt_bwd_ttl_max
                pkt_fwd_ttl_pre = pkt_now_ttl if dir == 'fwd' else pkt_fwd_ttl_pre
                pkt_bwd_ttl_pre = pkt_now_ttl if dir == 'bwd' else pkt_bwd_ttl_pre
                
                pkt_time = pkt_now.time
                pkt_fwd_iat = pkt_time if dir == 'fwd' else pkt_fwd_iat_pre
                pkt_bwd_iat = pkt_time if dir == 'bwd' else pkt_bwd_iat_pre
                pkt_fwd_iat_total += pkt_time if dir == 'fwd' else 0
                pkt_bwd_iat_total += pkt_time if dir == 'bwd' else 0
                pkt_fwd_iat_var = abs(pkt_fwd_iat_pre - pkt_time) if (dir == 'fwd' and first_fwd) else pkt_fwd_iat_var
                pkt_bwd_iat_var = abs(pkt_bwd_iat_pre - pkt_time) if (dir == 'bwd' and first_bwd) else pkt_bwd_iat_var
                pkt_fwd_iat_min = pkt_time if((not first_fwd or pkt_fwd_iat_min > pkt_time) and dir == 'fwd') else pkt_fwd_iat_min
                pkt_bwd_iat_min = pkt_time if((not first_bwd or pkt_bwd_iat_min > pkt_time) and dir == 'bwd') else pkt_bwd_iat_min
                pkt_fwd_iat_max = pkt_time if((not first_fwd or pkt_fwd_iat_max < pkt_time) and dir == 'fwd') else pkt_fwd_iat_max
                pkt_bwd_iat_max = pkt_time if((not first_bwd or pkt_bwd_iat_max < pkt_time) and dir == 'bwd') else pkt_bwd_iat_max
                pkt_fwd_iat_pre = pkt_time if dir == 'fwd' else pkt_fwd_iat_pre
                pkt_bwd_iat_pre = pkt_time if dir == 'bwd' else pkt_bwd_iat_pre

                if(dir == 'fwd'):
                    first_fwd = True
                if(dir == 'bwd'):
                    first_bwd = True

                pkt_info[f"{i}_fwd_pktMeanSize"]  = pkt_fwd_length
                pkt_info[f"{i}_bwd_pktMeanSize"]  = pkt_bwd_length
                pkt_info[f"{i}_fwd_pktTotalSize"] = pkt_fwd_length_total
                pkt_info[f"{i}_bwd_pktTotalSize"] = pkt_bwd_length_total
                pkt_info[f"{i}_fwd_pktVarSize"]	  = pkt_fwd_length_var
                pkt_info[f"{i}_bwd_pktVarSize"]   = pkt_bwd_length_var
                pkt_info[f"{i}_fwd_pktMinSize"]	  = pkt_fwd_length_min
                pkt_info[f"{i}_bwd_pktMinSize"]	  = pkt_bwd_length_min
                pkt_info[f"{i}_fwd_pktMaxSize"]   = pkt_fwd_length_max
                pkt_info[f"{i}_bwd_pktMaxSize"]	  = pkt_bwd_length_max
                pkt_info[f"{i}_fwd_iatMean"]      = pkt_fwd_iat
                pkt_info[f"{i}_bwd_iatMean"]      = pkt_bwd_iat
                pkt_info[f"{i}_fwd_iatTotal"]     = pkt_fwd_iat_total
                pkt_info[f"{i}_bwd_iatTotal"]     = pkt_bwd_iat_total
                pkt_info[f"{i}_fwd_iatVar"]       = pkt_fwd_iat_var
                pkt_info[f"{i}_bwd_iatVar"]       = pkt_bwd_iat_var
                pkt_info[f"{i}_fwd_iatMin"]       = pkt_fwd_iat_min
                pkt_info[f"{i}_bwd_iatMin"]       = pkt_bwd_iat_min
                pkt_info[f"{i}_fwd_iatMax"]       = pkt_fwd_iat_max
                pkt_info[f"{i}_bwd_iatMax"]       = pkt_bwd_iat_max
                pkt_info[f"{i}_fwd_ttlMeanSize"]  = pkt_fwd_ttl
                pkt_info[f"{i}_bwd_ttlMeanSize"]  = pkt_bwd_ttl
                pkt_info[f"{i}_fwd_ttlTotalSize"] = pkt_fwd_ttl_total
                pkt_info[f"{i}_bwd_ttlTotalSize"] = pkt_bwd_ttl_total
                pkt_info[f"{i}_fwd_ttlVarSize"]   = pkt_fwd_ttl_var
                pkt_info[f"{i}_bwd_ttlVarSize"]   = pkt_bwd_ttl_var
                pkt_info[f"{i}_fwd_ttlMaxSize"]	  = pkt_fwd_ttl_max
                pkt_info[f"{i}_bwd_ttlMaxSize"]   = pkt_bwd_ttl_pre
            pkt_info["LABEL"] = folder_name
            packet_stats.append(pkt_info)
            session_info["pktVarSize"] += abs(pkts[0][0]['IP'].len - pkts[7][0]['IP'].len)
            session_info["pktVarSize"] /= 8
            if pkts[0][0].haslayer('TCP'):
                session_info["windowVar"] += abs(pkts[0][0]['TCP'].window - pkts[7][0]['TCP'].window)
                session_info["windowVar"] /= 8
            session_info["pktMeanSize"] = session_info["pktTotalSize"] / 8
            session_info["windowMean"] = session_info["windowTotal"] / 8
            session_info["LABEL"] = folder_name
            session_stats.append(session_info)
            packet_5tuple_stats.append(pkt_5tuple_info)
        # Write into packet vector csv
        if os.path.exists(file_path_pv):
            df = pd.DataFrame(packet_stats)
            df.to_csv(file_path_pv, mode='a', header=False, index=False)
        else:
            df = pd.DataFrame(packet_stats)
            df.to_csv(file_path_pv, mode='w', index=False)

        # Write into session statistic csv
        if os.path.exists(file_path_ss):
            df = pd.DataFrame(session_stats)
            df.to_csv(file_path_ss, mode='a', header=False, index=False)
        else:
            df = pd.DataFrame(session_stats)
            df.to_csv(file_path_ss, mode='w', index=False)

        # Write into 5 tuple statistic csv
        if os.path.exists(file_path_5tuple):
            df = pd.DataFrame(packet_5tuple_stats)
            df.to_csv(file_path_5tuple, mode='a', header=False, index=False)
        else:
            df = pd.DataFrame(packet_5tuple_stats)
            df.to_csv(file_path_5tuple, mode='w', index=False)

        print(f"{join(folder_path, file)} Done~!")
