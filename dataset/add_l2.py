from scapy.all import rdpcap, wrpcap, Ether, Raw
import os

dataset_path = "./archive/Network-Traffic-Dataset/"
for folder in os.listdir(dataset_path):
    class_path = os.path.join(dataset_path, folder)
    if os.path.isdir(class_path):
        for file in os.listdir(class_path):
            file_path = os.path.join(class_path, file)
            print(file_path)
            if file.endswith(".pcapng") or file.endswith(".pcap"):
                packets = rdpcap(file_path)
                file_name, _ = os.path.splitext(file)
                
                new_packets = []

                for packet in packets:
                    if Ether not in packet:
                        # Mac address is arbitrary
                        ether = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB", type=0x0800)
                        new_packet = ether / packet
                        new_packets.append(new_packet)
                    else:
                        new_packets.append(packet)

                output_file = os.path.join(class_path, file)
                wrpcap(output_file, new_packets)

