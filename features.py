from scapy.all import rdpcap, DNSQR, IP
import pandas as pd

def extract_dns_features(pcap_file):
    packets = rdpcap(pcap_file)
    dns_features = []

    for packet in packets:
        if DNSQR in packet and IP in packet:
            dns_query = packet[DNSQR]
            dns_features.append({
                'Timestamp': packet.time,
                'Source IP': packet[IP].src,
                'Destination IP': packet[IP].dst,
                'Query': dns_query.qname.decode('utf-8'),
                'Query Type': dns_query.qtype,
                'Query Class': dns_query.qclass,
                'Response Code': dns_query.rcode if hasattr(dns_query, 'rcode') else None
            })

    return dns_features

def save_dns_features_to_csv(dns_features, output_file):
    df = pd.DataFrame(dns_features)
    df.to_csv(output_file, index=False)
    print(f"DNS features saved to {output_file}")

if __name__ == "__main__":
    pcap_file = 'capturefile.pcapng'
    output_csv = 'dns_captured.csv'

    dns_features = extract_dns_features(pcap_file)
    save_dns_features_to_csv(dns_features, output_csv)

