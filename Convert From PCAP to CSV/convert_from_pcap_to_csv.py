import sys
import os
import hashlib
import pandas as pd
import os.path, time

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.l2 import ARP, Ether, Dot3
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.handshake import TLSClientHello
from scapy.contrib.mpls import MPLS
from scapy.all import sniff, wrpcap, DNS, IP, UDP

from datetime import datetime, timedelta
from copy import deepcopy
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


fh = logging.FileHandler("extract_data_from_pcap_v2.log")
fh.setLevel(logging.INFO)

logger.addHandler(fh)

import geoip2.database
import geoip2.errors
# Path to the GeoLite2 database file
geo_db_path = '/home/quser/workspace/pcap_files_poc/GeoLite2-City.mmdb'
reader = geoip2.database.Reader(geo_db_path)
# Function to get country and region from IP
def get_country_region(ip):
    try:
        response = reader.city(ip)
        country = response.country.name
        region = response.subdivisions.most_specific.name
        return country, region
    except geoip2.errors.AddressNotFoundError:
        return None, None

from collections import defaultdict
def count_flows(pcap_file):
    flows = defaultdict(list)
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            if UDP in pkt:
                flow_key = (ip_layer.src, ip_layer.dst, pkt[UDP].sport, pkt[UDP].dport, ip_layer.proto)
            elif TCP in pkt:
                flow_key = (ip_layer.src, ip_layer.dst, pkt[TCP].sport, pkt[TCP].dport, ip_layer.proto)
            elif ICMP in pkt:
                icmp_layer = pkt[ICMP]
                flow_key = (ip_layer.src, ip_layer.dst, icmp_layer.type, ip_layer.proto)
            else:
                continue  # Skip other protocols
            flows[flow_key].append(pkt)
    return len(flows) #TCP/UDP/UCMP

def get_sha256_checksum(filename):
  with open(filename, "rb") as f:
    # Create a SHA256 hash object
    sha256_hash = hashlib.sha256()
    # Read the file in chunks of 4096 bytes
    for chunk in iter(lambda: f.read(4096), b""):
      sha256_hash.update(chunk)
    # Get the final SHA256 digest in hexadecimal format
    return sha256_hash.hexdigest()


IS_MALWARE = None


# Define known file signatures
FILE_SIGNATURES = {
    b'\x50\x4B\x03\x04': ('ZIP', 'zip'),
    b'\xFF\xD8\xFF': ('JPEG', 'jpeg'),
    b'\x25\x21\x50\x53': ('PostScript', 'ps'),
    b'%PDF': ('PDF', 'pdf'),
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('PNG', 'png'),
    b'\x25\x50\x44\x46': ('PDF', 'pdf'),
    b'\x42\x4D': ('BMP', 'bmp'),
    b'\x49\x49\x2A\x00': ('TIFF', 'tiff'),
    b'\x4D\x4D\x00\x2A': ('TIFF', 'tiff'),
    b'\x25\x21\x50\x53': ('PS', 'ps')
}


L_PROTOCOLS = { "p_ip"      : "IP",
                "p_tcp"     : "TCP",
                "p_arp"     : "ARP",
                "p_icmp"    : "ICMP",
                "p_http"    : "HTTP",
                "p_https"   : "HTTPS",
                "p_ftp"     : "FTP",
                "p_sftp"    : "SFTP",
                "p_tftp"    : "TFTP",
                "p_ssh"     : "SSH",
                "p_smtp"    : "SMTP",
                "p_smtps"   : "SMTPS",
                "p_dns"     : "DNS",
                "p_snmp"    : "SNMP",
                "p_rdp"     : "RDP",
                "p_sql"     : "SQL",
                "p_sqlnet"  : "SQLNET",
                "p_mysql"   : "MSQL",
                "p_pop3"    : "POP3",
                "p_pop3s"   : "POP3S",
                "p_smb"     : "SMB",             
                "p_other"   : "OTHER" }

# Initialize packet information dictionary
PACKET_INFO = { "filename" :  None,
                "file_sha256": None,
                "timestamp": None,
                "datetime": None,
                "working_hours": None,
                "weekend": None,
                "src_ip": None,
                "src_ip_country": None,
                "src_ip_region": None,
                "dst_ip": None,
                "dst_ip_country": None,
                "dst_ip_region": None,
                "ip_version": None,     #ToDo
                "length": None,
                "l1_protocol": None,
                "l2_protocol": None,
                "l3_protocol": None,
                "l4_protocol": None,
                "protocol": None,
                "src_port": None,
                "dst_port": None,
                "src_mac": None,
                "dst_mac": None,
                "ssh": False,
                "telnet": False,
                "ftp": False,
                "scm": False,            #Simple control messages:Some applications might use UDP for simple commands or status updates with custom data formats.
                "query_name": None,
                "response": None,
                "http_info": None,
                "http_status_code": None,
                "http_method": None,
                "http_host": None,
                "http_path": None,
                "irc_info": None,
                "ssl_info": None,
                "file_type": None,
                "file_extension": None,
                "icmp_type": None,
                "icmp_code": None,
                "icmp_id": None,
                "icmp_seq": None,
                "icmp_checksum": None,
                "hostname": None,
                "vendor_class_id": None,
                "imap_info": None,
                "cipher_suites": None,
                "content_type": None,
                "tcp_flags": None,
                "packet_loss": 0,
                "ldap": False,
                "ldap_payload": None,
                "tos": None,             #ToDo: DSCP/TOS (Type of Service)
                "ttl": None,             #ToDo: Time to Live (TTL)
                "is_arp": None,          #Todo: Is ARP
                "arp_operation": None,   #Todo: Operation (ARP request, ARP reply)
                "header_length": None,   #ToDo: IP Layer - Header Length
                "total_length": None,    #ToDo: IP Layer - Total Length
                "header_checksum": None, #ToDo: IP Layer - Header Checksum
                "label":IS_MALWARE
            }


def is_weekend(dt):
  return dt.weekday() in [5, 6]

def is_working_hours(dt):
  return 8 <= dt.hour < 18

def classify_datetime(dt):
  if is_weekend(dt):
    return True, False
  elif is_working_hours(dt):
    return False, True
  else:
    return False, False

# Function to group by each column and compute the mean of other numeric columns
def group_by_each_column(df):
    result = {}
    for column in df.columns:
        # Group by the current column
        grouped = df.groupby(column).mean()
        # Store the result in the dictionary
        result[column] = grouped
    # Print the results
    for col, grouped_df in grouped_results.items():
        print(f"\nGrouped by column '{col}':")
        print(grouped_df)

def get_ip_version(packet):
  # Check if the packet is an IP packet
  if IP in packet:
    ip_header = packet[IP]
    return ip_header.version
  else:
    return None

# Define a function to classify packets
def classify_packet(packet):
    ether_arp_count = 0
    ether_dot11_count = 0
    ether_mpls_count = 0
    ether_ip_icmp_count = 0
    ether_ip_tcp_count = 0
    ether_ip_udp_count = 0
    ether_ip_other_count = 0
    ether_other_count = 0
    dot3_count = 0
    ppp_count = 0
    fddi_count = 0
    other_count = 0

    for packet in packets:
        if Ether in packet:
            eth_frame = packet[Ether]
            if ARP in packet:
                print(f"ARP Packet: {packet.summary()}")
                ether_arp_count = ether_arp_count + 1 
            
            elif Dot11 in packet:
                print(f"802.11 Frame: {packet.summary()}")
                ether_dot11_count = ether_dot11_count + 1
            
            elif MPLS in packet:
                print(f"MPLS Packet: {packet.summary()}")
                ether_mpls_count = ether_mpls_count + 1
            
            elif IP in packet or IPv6 in packet:
                if ICMP in packet:
                    print(f"ICMP Packet: {packet.summary()}")
                    ether_ip_icmp_count = ether_ip_icmp_count + 1
                
                elif TCP in packet:
                    print(f"TCP Segment: {packet.summary()}")
                    ether_ip_tcp_count = ether_ip_tcp_count + 1
                
                elif UDP in packet:
                    print(f"UDP Datagram: {packet.summary()}")
                    ether_ip_udp_count = ether_ip_udp_count + 1
                else:
                    print(f"IP Packet: {packet.summary()}")
                    ether_ip_other_count = ether_ip_other_count + 1
            else:
                print(f"Ethernet Frame: {packet.summary()}")
                ether_other_count = ether_other_count + 1
        
        elif Dot3 in packet:
            print(f"Token Ring Frame: {packet.summary()}")
            dot3_count = dot3_count + 1
        elif PPP in packet:
            print(f"PPP Frame: {packet.summary()}")
            ppp_count = ppp_count + 1
        elif FDDI in packet:
            print(f"FDDI Frame: {packet.summary()}")
            fddi_count = fddi_count + 1
        else:
            print(f"Unknown Packet Type: {packet.summary()}")
            other_count = other_count + 1

    print(f"ARP Packet: {ether_arp_count}")
    print(f"802.11 Frame: {ether_dot11_count}")
    print(f"MPLS Packet: {ether_mpls_count}")
    print(f"ICMP Packet: {ether_ip_icmp_count}")
    print(f"TCP Segment: {ether_ip_tcp_count}")
    print(f"UDP Datagram: {ether_ip_udp_count}")
    print(f"Other IP Packet: {ether_ip_other_count}")
    print(f"Other Ethernet Frame: {ether_other_count}")
    print(f"Token Ring Frame: {dot3_count}")
    print(f"PPP Frame: {ppp_count}")
    print(f"FDDI Frame: {fddi_count}")
    print(f"Unknown Packet Type: {other_count}")


#HTTP Method Usage
# Function to extract HTTP information
def extract_http(packet):
    if packet.haslayer(scapy.Raw):
        http_payload = packet[scapy.Raw].load.decode(errors="ignore")
        if "GET " in http_payload or "POST " in http_payload:
            return http_payload.split('\r\n')[0]  # Return the first line of the HTTP request
    return None


#Web Traffic Response Code Analysis
# Function to extract HTTP response information with status codes
def extract_http_response(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors="ignore")
        lines = payload.split('\r\n')
        if lines:
            # Check for HTTP response status line
            if lines[0].startswith('HTTP/'):
                status_line = lines[0].split(' ', 2)
                if len(status_line) >= 2:
                    status_code = int(status_line[1])
                    return status_code
    return None


# Function to extract HTTP methods and associated details
def extract_http_info(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        method = http_layer.Method.decode()
        host = http_layer.Host.decode() if http_layer.Host else ""
        path = http_layer.Path.decode() if http_layer.Path else ""
        return method, host, path
    return None, None, None


# Function to extract Content-Type from HTTP response packets
def extract_content_type(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors="ignore")
        lines = payload.split('\r\n\r\n', 1)
        if len(lines) > 1:
            headers = lines[0].split('\r\n')
            for header in headers:
                if header.startswith('Content-Type:'):
                    content_type = header.split(':', 1)[1].strip()
                    return content_type
    return None


# Function to extract IRC information
def extract_irc(packet):
    if packet.haslayer(scapy.Raw):
        irc_payload = packet[scapy.Raw].load.decode(errors="ignore")
        if irc_payload.startswith("PASS") or irc_payload.startswith("NICK") or irc_payload.startswith("USER") or "PRIVMSG" in irc_payload:
            return irc_payload.split('\r\n')[0]  # Return the first line of the IRC message
    return None


# Function to extract SSL/TLS cipher suite information from Client Hello packets
def extract_ssl(packet):
    if packet.haslayer(scapy.TLS):
        try:
            tls_record = packet[scapy.TLS]
            if isinstance(tls_record.msg, scapy.TLSClientHello):
                cipher_suites = [cipher.hex() for cipher in tls_record.msg.cipher_suites]
                #print(cipher_suites)
                return cipher_suites
        except Exception as e:
            print(f"Error extracting SSL/TLS info: {e}")
    return None


# Function to extract SSL/TLS information
def extract_ssl(packet):
    if packet.haslayer(scapy.Raw):
        ssl_payload = packet[scapy.Raw].load[:4].hex()  # Return the first 4 bytes of the SSL/TLS payload as a hex string
        return ssl_payload
    return None


# Function to extract file information
def extract_file_info(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        for signature, (file_type, file_extension) in FILE_SIGNATURES.items():
            if payload.startswith(signature):
                return (file_type, file_extension)
    return (None, None)


# Function to extract device information
def extract_device_info(packet, packet_info):
    if packet.haslayer(DHCP):
        dhcp_layer = packet[DHCP]
        if dhcp_layer.options:
            for opt in dhcp_layer.options:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    packet_info["hostname"] = opt[1]
                if isinstance(opt, tuple) and opt[0] == 'vendor_class_id':
                    packet_info["vendor_class_id"] = opt[1]
    return packet_info


# Function to extract IMAP information
def extract_imap(packet):
    if packet.haslayer(scapy.Raw):
        imap_payload = packet[scapy.Raw].load.decode(errors="ignore")
        # Simple check for common IMAP commands
        if any(cmd in imap_payload for cmd in ["LOGIN", "SELECT", "FETCH", "LOGOUT", "STORE", "SEARCH", "NOOP", "EXAMINE"]):
            return imap_payload.split('\r\n')[0]  # Return the first line of the IMAP command
    return None


#not working coreectly
# Function to extract Client Cipher Suite Usage
def extract_cipher_suites(packet):
    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        if client_hello.ciphers:
            return [cipher for cipher in client_hello.ciphers]
    return None


# Function to extract TCP flags
def extract_tcp_flags(packet):
    if scapy.TCP in packet:
        flags = packet[scapy.TCP].flags
        flag_names = []
        if flags & 0x02:
            flag_names.append('SYN')
        if flags & 0x10:
            flag_names.append('ACK')
        if flags & 0x01:
            flag_names.append('FIN')
        if flags & 0x04:
            flag_names.append('RST')
        if flags & 0x08:
            flag_names.append('PSH')
        if flags & 0x20:
            flag_names.append('URG')
        return ','.join(flag_names)
    return None


# Function to detect packet loss
def detect_packet_loss(packet, streams):
    if scapy.TCP in packet:
        tcp_layer = packet[scapy.TCP]
        stream_id = (packet[scapy.IP].src, packet[scapy.IP].dst, tcp_layer.sport, tcp_layer.dport)
        seq = tcp_layer.seq
        ack = tcp_layer.ack
        payload_len = len(tcp_layer.payload)
        
        if stream_id not in streams:
            streams[stream_id] = {'last_seq': seq, 'packet_loss': 0}
        else:
            expected_seq = streams[stream_id]['last_seq'] + 1
            if seq > expected_seq:
                streams[stream_id]['packet_loss'] += (seq - expected_seq)
            streams[stream_id]['last_seq'] = seq + payload_len

        return streams[stream_id]['packet_loss']
    return None


# Function to extract SMB OS version information
def extract_smb_os_info(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        if b'Windows' in payload:
            os_info = payload.split(b'Windows')[1].split(b'\x00')[0].decode(errors='ignore')
            return f'Windows {os_info.strip()}'
        elif b'Unix' in payload:
            os_info = payload.split(b'Unix')[1].split(b'\x00')[0].decode(errors='ignore')
            return f'Unix {os_info.strip()}'
    return None


# Function to extract NetBIOS destination information
def extract_netbios_info(packet):
    if packet.haslayer(scapy.NBTDatagram):
        netbios_info = packet[scapy.NBTDatagram].summary()
        return netbios_info
    elif packet.haslayer(scapy.NBNSRequest):
        netbios_info = packet[scapy.NBNSRequest].summary()
        return netbios_info
    return None


# Function to extract LDAP information
def extract_ldap_info(packet):
    return packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None


def extract_icmp_info(packet):
    icmp_info = {"type": None, "code": None, "id": None, "seq": None, "checksum": None }
    if packet.haslayer(ICMP):
        icmp_info["type"] = packet[ICMP].type
        icmp_info["code"] = packet[ICMP].code
        # Extract other relevant fields based on ICMP type/code
        # (e.g., sequence number for echo requests/replies)
        if packet[ICMP].type == 8 and packet[ICMP].code == 0:  # Echo request
            icmp_info["id"] = packet[ICMP].id
            icmp_info["seq"] = packet[ICMP].seq
        # checks for other ICMP types/codes
        icmp_info["checksum"] = packet[ICMP].chksum
    return icmp_info

#Layer - 3 : Transport Layer Protocol
#Check if it's an TCP packet 
def ETHER_TCP_DPI(packet, tcp_layer, packet_info):
    logger.info("----------------------------###LAYER 3###---------------------")
    # Dictionary to store Content-Type distribution
    content_type_distribution = {}
    streams = {}

    packet_info["src_port"] = tcp_layer.sport
    packet_info["dst_port"] = tcp_layer.dport
    packet_info["tcp_flags"] = extract_tcp_flags(packet)
    packet_info["packet_loss"] = detect_packet_loss(packet, streams)

    #Layer-4
    # Check if it's an HTTP packet
    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "HTTP"
        packet_info["http_info"] = extract_http(packet)
        http_status_code = extract_http_response(packet)
        method, host, path = extract_http_info(packet)
        packet_info["http_method"] = method
        packet_info["http_host"] = host
        packet_info["http_path"] = path
        if http_status_code:
            packet_info["http_status_code"] = http_status_code
            print(packet_info["http_status_code"])
        content_type = extract_content_type(packet)
        if content_type:
            packet_info["content_type"] = content_type
            print(packet_info["content_type"])
    
    #Layer-4
    # Check if it's an HTTPS packet
    if tcp_layer.dport == 443 or tcp_layer.sport == 443:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "HTTPS"
        #packet_info["protocol"] = "SSL/TLS"
        packet_info["ssl_info"] = extract_ssl(packet)
        packet_info["cipher_suites"] = extract_cipher_suites(packet)


    #???????
    content_type = extract_content_type(packet)
    if content_type:
        if content_type in content_type_distribution:
            content_type_distribution[content_type] += 1
        else:
            content_type_distribution[content_type] = 1
    
    #Layer-4
    # Check if the packet is SSH traffic
    if tcp_layer.sport == 22 or tcp_layer.dport == 22:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SSH"
        #packet_info["ssh"] = True

    #Layer-4
    #Check if the packet is Telnet traffic
    if tcp_layer.sport == 23 or tcp_layer.dport == 23:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "TELNET"
        #packet_info["telnet"] = True

    #Layer-4
    # Check if the packet is FTP traffic
    if tcp_layer.sport == 21 or tcp_layer.dport == 21 or tcp_layer.sport == 20 or tcp_layer.dport == 20:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "FTP"
        #packet_info["ftp"] = True
    
    # Check if the packet is SFTP traffic
    if tcp_layer.sport == 22 or tcp_layer.dport == 22:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SFTP"
        #packet_info["ftp"] = True

    # Check if the packet is SMTP traffic
    if tcp_layer.sport == 25 or tcp_layer.dport == 25:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SMTP"
        #packet_info["ftp"] = True

    # Check if the packet is SMTPS traffic
    if tcp_layer.sport == 587 or tcp_layer.dport == 587:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SMTPS"
        #packet_info["ftp"] = True

    # Check if the packet is POP3 traffic
    if tcp_layer.sport == 110 or tcp_layer.dport == 110:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "POP3"
        #packet_info["ftp"] = True

    # Check if the packet is POP3S traffic
    if tcp_layer.sport == 995 or tcp_layer.dport == 995:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "POP3S"
        #packet_info["ftp"] = True


    # Check if the packet is SQL traffic
    if tcp_layer.sport == 1433 or tcp_layer.dport == 1433:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SQL"
        #packet_info["ftp"] = True


    # Check if the packet is SQLNET traffic
    if tcp_layer.sport == 1521 or tcp_layer.dport == 1521:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SQLNET"
        #packet_info["ftp"] = True


    # Check if the packet is MYSQL traffic
    if tcp_layer.sport == 3306 or tcp_layer.dport == 3306:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "MYSQL"
        #packet_info["ftp"] = True


    # Check if the packet is RDP traffic
    if tcp_layer.sport == 3389 or tcp_layer.dport == 3389:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "RDP"
        #packet_info["ftp"] = True

    #Layer-4
    # Check if it's an IRC packet
    if tcp_layer.sport == 6667 or tcp_layer.dport == 6667:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "IRC"
        #packet_info["protocol"] = "IRC"
        packet_info["irc_info"] = extract_irc(packet)
    
    #Layer-4
    # Check if it's an IMAP packet
    if tcp_layer.sport == 143 or tcp_layer.dport == 143 or tcp_layer.sport == 993 or tcp_layer.dport == 993:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "IMAP"
        #packet_info["protocol"] = "IMAP"
        packet_info["imap_info"] = extract_imap(packet)
    

    #Layer-4
    # Check if it's an IMAPS packet
    if tcp_layer.sport == 995 or tcp_layer.dport == 995 :
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "IMAP"
        #packet_info["protocol"] = "IMAP"
        #packet_info["imap_info"] = extract_imap(packet)
    
    #Layer-4
    # Check if it's an LDAP packet
    if tcp_layer.sport == 389 or tcp_layer.dport == 389:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "LDAP"
        #packet_info["ldap"] = True
        packet_info["ldap_payload"] = extract_ldap_info(packet)
    
    #Layer-4
    # Check if it's an SMB packet
    if tcp_layer.sport == 445 or tcp_layer.dport == 445 or tcp_layer.sport == 139 or tcp_layer.dport == 139:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "SMB"
        smb_os_versions = set()
        smb_traffic_exists = True
        smb_os_info = extract_smb_os_info(packet)
        if smb_os_info:
            smb_os_versions.add(smb_os_info)
        if smb_traffic_exists:
            if smb_os_versions:
                print("OS Versions detected in SMB traffic:")
                for os_version in smb_os_versions:
                    print(f" - {os_version}")
        else:
            print("No SMB Traffic detected in the PCAP file.")


    # Check if it's a file (ZIP, JPEG, PS, etc.)
    file_type, file_extension = extract_file_info(packet)
    if file_type:
        packet_info["file_type"] = file_type
        packet_info["file_extension"] = file_extension
    # Check if it's a file (ZIP, JPEG, PS, etc.)
    file_type, file_extension = extract_file_info(packet)
    if file_type:
        packet_info["file_type"] = file_type
        packet_info["file_extension"] = file_extension
    return packet_info

#Layer - 3: Transport Layer Protocol
#Check if it's an UDP packet 
def ETHER_UDP_DPI(packet, udp_layer, packet_info):
    logger.info("----------------------------###LAYER 3###---------------------")
    packet_info["src_port"] = udp_layer.sport
    packet_info["dst_port"] = udp_layer.dport 
    
    #if packet.haslayer(DNS):
    # Check if the packet is TFTP traffic
    if udp_layer.dport == 69 or udp_layer.sport == 69:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "TFTP"
     # Check if the packet is DHCP traffic
    elif udp_layer.sport == 67 or udp_layer.dport == 67 or udp_layer.sport == 68 or udp_layer.dport == 68:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "DHCP"
        packet_info  = extract_device_info(packet, packet_info) 
    # Check if the packet is RDP traffic
    elif udp_layer.sport == 3389 or udp_layer.dport == 3389:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "RDP"
        #packet_info["ftp"] = True
    # Check if it's an DNS packet
    elif udp_layer.dport == 53 or udp_layer.sport == 53:
        logger.info("----------------------------###LAYER 4###---------------------")
        packet_info["l4_protocol"] = "DNS"
        # Check if it's a DNS query
        if packet.haslayer(DNSQR):
            dns_query = packet[DNSQR]
            packet_info["query_name"] = dns_query.qname.decode("utf-8")
            #print(packet_info["query_name"])
        elif packet.haslayer(DNSRR):
            dns_response = packet[DNSRR]
            packet_info["response"] = dns_response.rdata
            #print(packet_info["response"])
    
    if (packet.haslayer(UDP) and len(packet.payload) < 100 and not packet.haslayer(DNS)):
        packet_info["scm"] = True

    return packet_info


#Layer -2 
def ETHER_DPI(packet, packet_info, 
              ip_packet_count, 
              tcp_packet_count, 
              icmp_packet_count, 
              udp_packet_count, 
              arp_packet_count, 
              other_ip_packet_count, other_packet_count):
    streams = {}

    if packet.haslayer(IP):
        ip_packet_count += 1
        packet_info["l2_protocol"] = "IP"
        packet_info["ip_version"] = get_ip_version(packet)
        packet_info["timestamp"] = float(packet.time)
        packet_datetime = datetime.fromtimestamp(float(packet.time))
        is_weekend, is_working_hours = classify_datetime(packet_datetime)
        packet_info["datetime"] = packet_datetime
        packet_info["working_hours"] = is_working_hours
        packet_info["weekend"] = is_weekend

        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
        packet_info["src_ip_country"], packet_info["src_ip_region"] = get_country_region(packet[IP].src)
        packet_info["dst_ip_country"], packet_info["dst_ip_region"] = get_country_region(packet[IP].dst)

        packet_info["length"] = len(packet)    

        logger.info("----------------------------###LAYER 2###---------------------")
        
        # Identify protocol and set relevant fields
        if packet.haslayer(TCP):
            logger.info("----------------------------###LAYER 3###---------------------")
            tcp_packet_count += 1
            packet_info["l3_protocol"] = "TCP"
            tcp_layer = packet[TCP]
            packet_info = ETHER_TCP_DPI(packet, tcp_layer, packet_info)
        #######################   TCP   ###########################
        elif packet.haslayer(UDP):
            logger.info("----------------------------###LAYER 3###---------------------")
            udp_packet_count += 1
            packet_info["l3_protocol"] = "UDP"
            udp_layer = packet[UDP]
            packet_info = ETHER_UDP_DPI(packet, udp_layer, packet_info)
        #########################  UDP  #########################
        elif packet.haslayer(ICMP):
            logger.info("----------------------------###LAYER 3###---------------------")
            icmp_packet_count += 1
            packet_info["l3_protocol"] = "ICMP"
            icmp_info = extract_icmp_info(packet)
            packet_info["icmp_type"] = icmp_info["type"]
            packet_info["icmp_code"] = icmp_info["code"]
            packet_info["icmp_id"] = icmp_info["id"]
            packet_info["icmp_seq"] = icmp_info["seq"]
            packet_info["icmp_checksum"] = icmp_info["checksum"]
            #packet_info["protocol"] = "ICMP"
        #########################   ICMP  #########################         
        else: #
            other_ip_packet_count += 1
            packet_info["l3_protocol"] = "OTHER"
            #packet_info["protocol"] = "OTHER"
            # Append packet info to list
            #packet_data.append(packet_info)
        ##########################        ########################
    elif packet.haslayer(ARP):
        #print(f"ARP Frame")
        arp_packet_count += 1
        arp_layer = packet[ARP]
        packet_info["l2_protocol"] = "ARP"
        #packet_info["protocol"] = "ARP"
        packet_info["src_ip"] = arp_layer.psrc
        packet_info["dst_ip"] = arp_layer.pdst
        packet_info["src_ip_country"], packet_info["src_ip_region"] = get_country_region(src_ip)
        packet_info["dst_ip_country"], packet_info["dst_ip_region"] = get_country_region(dst_ip)
        packet_info["src_mac"] = arp_layer.hwsrc
        packet_info["dst_mac"] = arp_layer.hwdst
    #########################   ARP  #######################
    elif packet.haslayer(RadioTap):  # Check if radiotap header is present (indication of 802.11 capture)
        print(f"802.11 Frame")
    #########################   802.11 Frame  #########################
    elif packet.haslayer(MPLS):
        print(f"MPLS Packet")
    #########################   MPLS Packet  #########################
    else:
        other_packet_count += 1
        packet_info["l2_protocol"] = "OTHER"
        print("This Ether packet is not IP, ARP, 802.11, MPL packet")
    return packet_info, ip_packet_count, tcp_packet_count, icmp_packet_count, udp_packet_count, arp_packet_count, other_ip_packet_count, other_packet_count


def pcap_analysis(packets, filename, sha256_checksum):
    # List to store packet data
    packet_data = []    
    packet_count = 0
    ip_packet_count = 0
    tcp_packet_count = 0
    icmp_packet_count = 0
    udp_packet_count = 0
    arp_packet_count = 0
    other_packet_count = 0
    other_ip_packet_count = 0

    # Process packets
    for packet in packets:
        packet_count += 1
        packet_info = deepcopy(PACKET_INFO)
        packet_info["filename"] = filename
        packet_info["file_sha256"] = sha256_checksum
        
        if packet.haslayer(Ether):
            packet_info["l1_protocol"] = "ETHER"
            logger.info("----------------------------###LAYER 1###---------------------")
            packet_info, ip_packet_count, tcp_packet_count, icmp_packet_count, udp_packet_count, arp_packet_count, other_ip_packet_count, other_packet_count = ETHER_DPI(packet, packet_info, ip_packet_count, tcp_packet_count, icmp_packet_count, udp_packet_count, arp_packet_count, other_ip_packet_count, other_packet_count)        
        ########################   Ether   ########################
        elif Dot3 in packet:
            packet_info["l1_protocol"] = "DOT3"
            print(f"Token Ring Frame")
        ########################   Dot3   ########################
        elif PPP in packet:
            packet_info["l1_protocol"] = "PPP"
            print(f"PPP Frame")
        ########################   PPP   ########################
        elif FDDI in packet:
            packet_info["l1_protocol"] = "FDDI"
            print(f"FDDI Frame")
        ########################   FDDI   ########################
        else:
            print(f"Unknown Packet Type")


        # Extract device information
        packet_info  = extract_device_info(packet, packet_info)
        #packet_info.update(device_info)
        
        if packet_info["l2_protocol"]:  # Only append if a protocol was identified
            packet_data.append(packet_info)
    print("other_packet_count:", other_packet_count)
    print("other_ip_packet_count:", other_ip_packet_count)
    print("ip_packet_count:", ip_packet_count)
    print("arp_packet_count:", arp_packet_count)
    print("tcp_packet_count:", tcp_packet_count)
    print("icmp_packet_count:", icmp_packet_count)
    print("udp_packet_count:", udp_packet_count)
    print("Total Packet Count:", packet_count)
    #if other_ip_packet_count != 0:
        #exit()
    if (packet_count != (tcp_packet_count + udp_packet_count + icmp_packet_count + other_packet_count + other_ip_packet_count)):
        print('Error PACKET')
        exit()
    if (ip_packet_count != (tcp_packet_count + udp_packet_count + icmp_packet_count + other_ip_packet_count)):
        print('Error IP')
        exit()
    return packet_data

def print_columns(df):
    for name in df.columns:
        print("-" + name + "-")

def process_pcap_directory(input_dir, output_dir, output_file="pcap2dataframe_malware_v2.csv"):
    all_packet_data = []
    for filename in os.listdir(input_dir):
        if filename.endswith(".pcap"):
            print(f"PCAP File:\t{filename}")
            packet_data = []
            pcap_file_path = os.path.join(input_dir, filename)
            packets = scapy.rdpcap(pcap_file_path)
            sha256_chcksm = get_sha256_checksum(pcap_file_path)
            packet_data = pcap_analysis(packets, filename, sha256_chcksm)
            df_temp = pd.DataFrame(packet_data)
            print("--->", df_temp.shape)
            df_temp = df_temp.assign(label=IS_MALWARE)
            df_temp.to_csv(os.path.join(output_dir, filename + "_v2.csv"), index=False)
            print("Extracted csv path:", output_dir + filename + "_v2.csv")
            all_packet_data.extend(deepcopy(packet_data))
    
    df = pd.DataFrame(all_packet_data)
    df = df.assign(label=IS_MALWARE)
    df.to_csv(os.path.join(output_dir, output_file), index=False)
    print("----->", df["file_sha256"].value_counts())
    print("----->", df['src_port'].value_counts())
    print("----->", df['dst_port'].value_counts())
    print("----->", df['ftp'].value_counts())

def main(in_dir, out_dir):    
    process_pcap_directory(in_dir, out_dir)

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