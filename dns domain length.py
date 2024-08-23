import pyshark
import matplotlib.pyplot as plt
import seaborn as sns

def read_pcapng(file_path):   #Read DNS packets from a pcapng file.
    
    capture = pyshark.FileCapture(file_path, display_filter='dns') # Read pcap file and filterd DNs packets
    return capture
    
def analyze_dns_query_length(capture):    #Analyze DNS query lengths from the captured packets.
                                                  
    dns_queries = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name) #captured packets extract DNS query name
    
    query_length_results = []
    for query in dns_queries:
        query_length = len(query)
        query_length_results.append((query, query_length))
        print(f"Domain: {query}, Length: {query_length}")
    """calculate each query name length and store the results """

    return query_length_results

if __name__ == "__main__":
    pcapng_file = 'capturefile.pcapng'   # Read DNS traffic from a pcapng file
    capture = read_pcapng(pcapng_file)

    # Analyze DNS query and its lengths from captured DNS packet
    query_length_results = analyze_dns_query_length(capture)


    # Prepare data for plotting
    domains = [result[0] for result in query_length_results]
    lengths = [result[1] for result in query_length_results]

    # Bar Chart: Length of each DNS query
    plt.figure(figsize=(14, 7))
    sns.barplot(x=domains, y=lengths, palette='viridis')
    plt.title('Length of Each DNS Query')
    plt.xlabel('Domain')
    plt.ylabel('Length')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    # Pie Chart: Proportion of different query lengths
    unique_lengths = list(set(lengths))
    length_counts = [lengths.count(length) for length in unique_lengths]
    colors = sns.color_palette('viridis', len(unique_lengths))

    plt.figure(figsize=(8, 8))
    plt.pie(length_counts, labels=unique_lengths, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.title('Proportion of Different Query Lengths')
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

    # Histogram: Distribution of query lengths
    plt.figure(figsize=(10, 6))
    sns.histplot(lengths, bins=20, kde=True, color='blue')
    plt.title('Distribution of Query Lengths')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.show()

    # Boxplot: Summary of query lengths
    plt.figure(figsize=(10, 6))
    sns.boxplot(x=lengths, palette='viridis')
    plt.title('Boxplot of Query Lengths')
    plt.xlabel('Length')
    plt.tight_layout()
    plt.show()
