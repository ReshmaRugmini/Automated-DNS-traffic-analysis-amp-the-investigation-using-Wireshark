import pyshark
import math
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns

def shannon_entropy(domain):
    """
    Calculate the Shannon entropy of a domain.
    """
    domain = domain.lower()
    freq = Counter(domain)
    entropy = -sum((count / len(domain)) * math.log2(count / len(domain)) for count in freq.values())
    return entropy

def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    return capture

def analyze_dns_entropy(capture):
    """
    Analyze DNS entropy from the captured packets.
    """
    dns_queries = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name)
    #captured packets extract DNS query name
    entropy_results = []
    high_entropy = []

    for query in dns_queries: #loop iterate over each DNS query in dns queries list
        entropy = shannon_entropy(query) # Using shannon_entropy fuct finding the entropy of DNS query
        entropy_results.append((query, entropy)) # contain query and entropy value as result
        if entropy > 3.5:  
            # print(f"High entropy domain detected: {query} with entropy {entropy:.2f}")
            high_entropy.append((query, entropy))
    

    return entropy_results,high_entropy

if __name__ == "__main__":
    # Read DNS traffic from a pcapng file
    pcapng_file = 'capturefile.pcapng'
    capture = read_pcapng(pcapng_file)

    # Analyze DNS entropy
    entropy_results,high_entropy = analyze_dns_entropy(capture)

    # Print results
    for domain, entropy in entropy_results:
        print(f"Domain: {domain}, Entropy: {entropy:.2f}")
    for domain, entropy in high_entropy:
        
        print(f"High entropy domain detected: {domain} with entropy {entropy:.2f}")
    print("//////////////////////////////////////")
    print(len(entropy_results))
    print(len(high_entropy))
    print("//////////////////////////////////////")

 # Prepare data for plotting
    domains = [result[0] for result in entropy_results]
    entropies = [result[1] for result in entropy_results]
    high_entropy_domains = [result[0] for result in high_entropy]
    high_entropies = [result[1] for result in high_entropy]

    # Bar Chart: Entropy of each domain
    plt.figure(figsize=(14, 7))
    sns.barplot(x=domains, y=entropies, palette='viridis')
    plt.title('Entropy of Each Domain')
    plt.xlabel('Domain')
    plt.ylabel('Entropy')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    # Pie Chart: Proportion of high entropy domains
    labels = ['High Entropy (> 3.5)', 'Other Domains']
    sizes = [len(high_entropy), len(entropy_results) - len(high_entropy)]
    colors = ['#ff9999','#66b3ff']
    
    explode = (0.1, 0)

    plt.figure(figsize=(8, 8))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.title('Proportion of High Entropy Domains')
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

    # Histogram: Distribution of entropy values
    plt.figure(figsize=(10, 6))
    sns.histplot(entropies, bins=20, kde=True, color='blue')
    plt.title('Distribution of Entropy Values')
    plt.xlabel('Entropy')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.show()