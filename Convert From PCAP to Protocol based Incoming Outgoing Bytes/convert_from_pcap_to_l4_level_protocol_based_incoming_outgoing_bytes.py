import os, sys
import os.path, time
import csv
import pandas as pd

from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import rdpcap, IP, TCP, UDP
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP

def print_dic(ip_to_HTTP_data):
    # Print a portion of the dictionary
    for i, ((src_ip, dst_ip), time_series_data) in enumerate(ip_to_HTTP_data.items()):
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        for timestamp, sizes in sorted(time_series_data.items())[:5]:  # First 5 timestamps
            print(f"  {timestamp}: {sizes}")
        if i >= 10:  # Stop after showing 10 IP pairs
            break

def process_pcap(pcap_file, output_dir):
    packets = rdpcap(pcap_file)

    # Data structure to store time series data
    # ip_to_HTTP_data = defaultdict(lambda: {"incoming": [], "outgoing": []})
    ip_to_ip_data = defaultdict(lambda: defaultdict(lambda: {
        'L4_HTTP_ingoing':  0, 'L4_HTTP_outgoing':  0,
        'L4_HTTPS_ingoing': 0, 'L4_HTTPS_outgoing': 0,
        'L4_FTP_ingoing':   0, 'L4_FTP_outgoing':   0,
        'L4_TELNET_ingoing':0, 'L4_TELNET_outgoing':0,
        'L4_SMTP_ingoing':  0, 'L4_SMTP_outgoing':  0,
        'L4_DNS_ingoing':   0, 'L4_DNS_outgoing':   0,
        'L4_SNMP_ingoing':  0, 'L4_SNMP_outgoing':  0,
        'L4_DHCP_ingoing':  0, 'L4_DHCP_outgoing':  0,
        'L4_Other_ingoing': 0, 'L4_Other_outgoing': 0,
        'L4_Total_ingoing': 0, 'L4_Total_outgoing': 0 }
        ))

    total_ip_to_ip_data = defaultdict(lambda: {
        'L4_Total_HTTP_ingoing':  0, 'L4_Total_HTTP_outgoing':  0,
        'L4_Total_HTTPS_ingoing': 0, 'L4_Total_HTTPS_outgoing': 0,
        'L4_Total_FTP_ingoing':   0, 'L4_Total_FTP_outgoing':   0,
        'L4_Total_TELNET_ingoing':0, 'L4_Total_TELNET_outgoing':0,
        'L4_Total_SMTP_ingoing':  0, 'L4_Total_SMTP_outgoing':  0,
        'L4_Total_DNS_ingoing':   0, 'L4_Total_DNS_outgoing':   0,
        'L4_Total_SNMP_ingoing':  0, 'L4_Total_SNMP_outgoing':  0,
        'L4_Total_DHCP_ingoing':  0, 'L4_Total_DHCP_outgoing':  0,
        'L4_Total_Other_ingoing': 0, 'L4_Total_Other_outgoing': 0
    })
  
    for packet in packets:
        #fromtimestamp(float(packet.time), timezone.utc)
        timestamp = packet.time
        pkt_time = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S.%f')
        #pkt_time = datetime.fromtimestamp(int(timestamp), timezone.utc)
        if packet.haslayer(IP):
            tcp_layer = packet.getlayer(TCP)
            udp_layer = packet.getlayer(UDP)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)  # Packet size in bytes  
            if tcp_layer:
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    #print("HTTP packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_HTTP_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_HTTP_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTP_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_HTTP_outgoing'] += pkt_size
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    #print("HTTPS packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_HTTPS_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_HTTPS_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTPS_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_HTTPS_outgoing'] += pkt_size
                elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                    #print("FTP packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_FTP_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_FTP_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_FTP_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_FTP_outgoing'] += pkt_size
                elif tcp_layer.dport == 23 or tcp_layer.sport == 23:
                    #print("TELNET packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_TELNET_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_TELNET_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_TELNET_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_TELNET_outgoing'] += pkt_size
                elif tcp_layer.dport == 25 or tcp_layer.sport == 25:
                    #print("SMTP packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_SMTP_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_SMTP_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SMTP_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_SMTP_outgoing'] += pkt_size
                elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                    #print("SSH packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_SSH_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_SSH_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SSH_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_SSH_outgoing'] += pkt_size
            elif udp_layer:
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    #print("DNS packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_DNS_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_DNS_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DNS_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_DNS_outgoing'] += pkt_size
                elif udp_layer.dport == 161 or udp_layer.sport == 161:
                    #print("SNMP packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_SNMP_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_SNMP_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SNMP_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_SNMP_outgoing'] += pkt_size
                elif udp_layer.dport == 67 or udp_layer.sport == 67 or \
                     udp_layer.dport == 68 or udp_layer.sport == 68:
                    #print("DHCP packet")
                    #Update total traffic size for src->dst
                    ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_DHCP_ingoing']  += pkt_size
                    # Update total traffic size for dst->src
                    ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_DHCP_outgoing'] += pkt_size
            
                    total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DHCP_ingoing']  += pkt_size
                    total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_DHCP_outgoing'] += pkt_size           
            else:
                # Update total traffic size for src->dst
                ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_Other_ingoing']    += pkt_size
                # Update total traffic size for dst->src
                ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_Other_outgoing']   += pkt_size
            
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_Other_ingoing']  += pkt_size
                total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_Other_outgoing'] += pkt_size
        else:
            # Update total traffic size for src->dst
            ip_to_ip_data[(src_ip, dst_ip)][pkt_time]['L4_Other_ingoing']    += pkt_size
            # Update total traffic size for dst->src
            ip_to_ip_data[(dst_ip, src_ip)][pkt_time]['L4_Other_outgoing']   += pkt_size
        

            total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_Other_ingoing']  += pkt_size
            total_ip_to_ip_data[(dst_ip, src_ip)]['L4_Total_Other_outgoing'] += pkt_size

    #print(total_ip_to_ip_data)
    for (src_ip, dst_ip), time_series_data in ip_to_ip_data.items():
        print(src_ip, dst_ip)
        all_timestamp_key = list(time_series_data.keys())
        start_time = all_timestamp_key[0]
        end_time = all_timestamp_key[-1]
        sorted_data = {}
        csv_filename = f"{output_dir}/{src_ip}_to_{dst_ip}.csv" 

        with open(csv_filename, mode='w', newline='') as csv_file:
            fieldnames = [
                    'timestamp', 'source_ip', 'destination_ip',
                    'L4_HTTP_ingoing' , 'L4_HTTP_outgoing' ,
                    'L4_HTTPS_ingoing', 'L4_HTTPS_outgoing',
                    'L4_FTP_ingoing'  , 'L4_FTP_outgoing'  ,
                    'L4_TELNET_ingoing', 'L4_TELNET_outgoing',
                    'L4_SMTP_ingoing' , 'L4_SMTP_outgoing' ,
                    'L4_DNS_ingoing'  , 'L4_DNS_outgoing'  ,
                    'L4_SNMP_ingoing' , 'L4_SNMP_outgoing' ,
                    'L4_DHCP_ingoing' , 'L4_DHCP_outgoing' ,
                    'L4_Other_ingoing', 'L4_Other_outgoing',
                    'L4_Total_ingoing', 'L4_Total_outgoing'
                ]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()  

            for current_time in all_timestamp_key:
                sorted_data[current_time] = time_series_data[current_time]

            for timestamp, sizes in sorted(sorted_data.items()):
                row = {'timestamp': timestamp, 'source_ip': src_ip, 'destination_ip': dst_ip}
                                
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTP_ingoing']     -= sizes['L4_HTTP_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTP_outgoing']    -= sizes['L4_HTTP_outgoing']
                
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTPS_ingoing']     -= sizes['L4_HTTPS_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_HTTPS_outgoing']    -= sizes['L4_HTTPS_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_FTP_ingoing']    -= sizes['L4_FTP_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_FTP_outgoing']   -= sizes['L4_FTP_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_TELNET_ingoing']   -= sizes['L4_TELNET_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_TELNET_outgoing']  -= sizes['L4_TELNET_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SMTP_ingoing']   -= sizes['L4_SMTP_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SMTP_outgoing']  -= sizes['L4_SMTP_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DNS_ingoing']   -= sizes['L4_DNS_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DNS_outgoing']  -= sizes['L4_DNS_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SNMP_ingoing']   -= sizes['L4_SNMP_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_SNMP_outgoing']  -= sizes['L4_SNMP_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DHCP_ingoing']   -= sizes['L4_DHCP_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_DHCP_outgoing']  -= sizes['L4_DHCP_outgoing']

                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_Other_ingoing']  -= sizes['L4_Other_ingoing']
                total_ip_to_ip_data[(src_ip, dst_ip)]['L4_Total_Other_outgoing'] -= sizes['L4_Other_outgoing']

                row.update(sizes)
                writer.writerow(row)
    #Check everything is calculated correctly
    for key, sub_dict in total_ip_to_ip_data.items():
        for sub_key in sub_dict.keys():
            if sub_dict[sub_key] != 0:
                print("Error.....", sub_key, sub_dict[sub_key])
                return
    print(f"Processed and exported data to {output_dir}")

def main(in_dir, out_dir):
    for filename in os.listdir(in_dir):
        if filename.endswith(".pcap"):
            print(f"PCAP File:\t{filename}")
            packet_data = []
            pcap_file_path = os.path.join(in_dir, filename)
            process_pcap(pcap_file_path, out_dir)

def run(in_dir, out_dir, IS_MALWARE):
    if not os.path.exists(in_dir):
        print(f"Directory: '{in_dir}' does not exist.")
        exit()
    print(f"\n\nPCAP Directory:\t\t{in_dir}")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    print(f"CSV Files will save:\t{out_dir}")
    print(f"DATASET is malware:\t{IS_MALWARE}\n\n")
    main(in_dir, out_dir)

if __name__ == "__main__":
  print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
  # Check if a parameter is provided
  if len(sys.argv) == 4 :
    in_dir = sys.argv[1]
    if not os.path.exists(in_dir):
        print(f"Directory: '{in_dir}' does not exist.")
        exit()         
    print(f"\n\nPCAP Directory:\t\t{in_dir}")

    out_dir = sys.argv[2]
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    print(f"CSV Files will save:\t{out_dir}")   
    
    IS_MALWARE = sys.argv[3]    
    print(f"DATASET is malware:\t{IS_MALWARE}\n\n")
    main(in_dir, out_dir)
  else:
    print("No input directory and output directory provided.")
