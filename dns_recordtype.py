import pyshark
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns

dns_record_type_labels = {'1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA', '12': 'PTR', '15': 'MX','16': 'TXT', 
'28': 'AAAA', '33': 'SRV', '99': 'SPF', '257': 'CAA', '48': 'DNSKEY','46': 'RRSIG', '47': 'NSEC', '50': 'NSEC3',
'52': 'TLSA', '55': 'HIP','56': 'NINFO','57': 'RKEY', '58': 'TALINK', '59': 'CDS', '60': 'CDNSKEY', '61': 'OPENPGPKEY',
'62': 'CSYNC', '63': 'ZONEMD', '64': 'SVCB', '65': 'HTTPS', '99': 'SPF', '249': 'TKEY', '250': 'TSIG',}
def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    return capture

def analyze_dns_record_types(capture):
    """
    Analyze DNS record types from the captured packets and identify unusual patterns.
    """
    
    dns_record_types = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            query = packet.dns.qry_name.lower()
            record_type = packet.dns.qry_type
            dns_record_types.append((query, record_type))

    record_type_counts = Counter(record_type for _, record_type in dns_record_types)
    domain_record_types = {query: record_type for query, record_type in dns_record_types}
    
    # Convert record type numeric values to labels
    record_type_counts = {dns_record_type_labels.get(record_type, record_type): count for record_type, count in record_type_counts.items()}
    domain_record_types = {query: dns_record_type_labels.get(record_type, record_type) for query, record_type in domain_record_types.items()}


    # Calculate total number of queries
    total_queries = len(dns_record_types)
    # Calculate the number of unique DNS record types
    unique_record_types = len(record_type_counts)

    # Calculate expected frequency of each record type
    expected_frequency = total_queries / unique_record_types

    # Identify unusual patterns (record types with frequency significantly different from expected)
    unusual_patterns = {}
    for record_type, null_record_count in record_type_counts.items():
        if null_record_count > expected_frequency * 1.5:  # Adjust the threshold as per your analysis
            unusual_patterns[record_type] = null_record_count

    return domain_record_types, record_type_counts, unusual_patterns, total_queries, unique_record_types

if __name__ == "__main__":

    pcapng_file='capturefile.pcapng'
    capture = read_pcapng(pcapng_file)

    domain_record_types, record_type_counts, unusual_patterns, total_queries, unique_record_types= analyze_dns_record_types(capture)

    for domain, record_type in domain_record_types.items():
        print(f"Domain: {domain}, Record Type: {record_type}")

    if unusual_patterns:
        print("\nUnusual Patterns Detected:")
        for record_type, null_record_count in unusual_patterns.items():
            print(f"{record_type}: {null_record_count} (higher than expected)")

    # Prepare data for plotting
    record_types = list(record_type_counts.keys())
    counts = list(record_type_counts.values())

    # Bar Chart: Count of each DNS record type
    plt.figure(figsize=(14, 7))
    sns.barplot(x=record_types, y=counts, palette='viridis')
    plt.title('Count of Each DNS Record Type')
    plt.xlabel('DNS Record Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Pie Chart: Proportion of different DNS record types
    colors = sns.color_palette('viridis', len(record_types))
    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=record_types, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.title('Proportion of Different DNS Record Types')
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

    # Heatmap: Unusual patterns in DNS record types
    if unusual_patterns:
        unusual_record_types = list(unusual_patterns.keys())
        unusual_counts = list(unusual_patterns.values())
        plt.figure(figsize=(12, 6))
        sns.heatmap([unusual_counts], annot=True, fmt="d", cmap='YlGnBu', xticklabels=unusual_record_types)
        plt.title('Unusual Patterns in DNS Record Types')
        plt.xlabel('Record Type')
        plt.ylabel('Unusual Count')
        plt.tight_layout()
        plt.show()

    else:
        print("\nNo NULL or Unusual Patterns Detected.")

        # Visualize overall distribution of DNS record types
        record_types = list(record_type_counts.keys())
        counts = list(record_type_counts.values())