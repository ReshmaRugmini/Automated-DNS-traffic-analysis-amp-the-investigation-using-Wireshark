import pyshark
from collections import Counter
import math
import matplotlib.pyplot as plt
import seaborn as sns

def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    return capture

def char_frequency_probability(domain):
    """
    Calculate the probability of each character in the domain.
    """
    domain = domain.lower()
    length = len(domain)
    freq = Counter(domain)
    probabilities = {char: count / length for char, count in freq.items()}
    return probabilities

def calculate_entropy(probabilities):
    """
    Calculate the Shannon entropy of the domain based on character probabilities.
    """
    entropy = -sum(p * math.log2(p) for p in probabilities.values())
    return entropy

def analyze_dns_signature(capture):
    """
    Analyze DNS signatures from the captured packets.
    """
    dns_queries = []
    dns_record_types = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            query = packet.dns.qry_name.lower()
            dns_queries.append(query)
            record_type = packet.dns.qry_type
            dns_record_types.append((query, record_type))

    char_freq_results = []
    query_length_results = []
    entropy_results = []

    for query in dns_queries:
        probabilities = char_frequency_probability(query)
        entropy = calculate_entropy(probabilities)
        char_freq_results.append((query, probabilities, entropy))
        entropy_results.append(entropy)

        query_length = len(query)
        query_length_results.append((query, query_length))

    record_type_counts = Counter(record_type for _, record_type in dns_record_types)
    domain_record_types = {query: record_type for query, record_type in dns_record_types}

    total_queries = len(dns_record_types)
    expected_frequency = total_queries / len(record_type_counts)

    unusual_patterns = {}
    for record_type, count in record_type_counts.items():
        if count > expected_frequency * 1.5:  
            unusual_patterns[record_type] = count

    # Plotting
    # 1. Character Frequency Distribution
    all_characters = [char for query, probabilities, _ in char_freq_results for char in probabilities]
    all_probabilities = [prob for query, probabilities, _ in char_freq_results for prob in probabilities.values()]
    
    plt.figure(figsize=(12, 6))
    plt.subplot(1, 3, 1)
    sns.histplot(all_probabilities, kde=True, bins=20)
    plt.title('Character Frequency Distribution')
    plt.xlabel('Probability')
    plt.ylabel('Frequency')

    # 2. Entropy Distribution
    plt.subplot(1, 3, 2)
    sns.histplot(entropy_results, kde=True, bins=20)
    plt.title('Entropy Distribution')
    plt.xlabel('Entropy')
    plt.ylabel('Frequency')

    # 3. DNS Query Length Distribution
    query_lengths = [length for query, length in query_length_results]
    
    plt.subplot(1, 3, 3)
    sns.histplot(query_lengths, kde=True, bins=20)
    plt.title('DNS Query Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Frequency')

    plt.tight_layout()
    plt.show()

    print("\nCharacter Frequency and Entropy Analysis:")
    for query, probabilities, entropy in char_freq_results:
        print(f"Domain: {query}, Character Frequencies: {probabilities}, Entropy: {entropy}")

    print("\nDNS Query Length Analysis:")
    for query, query_length in query_length_results:
        print(f"Domain: {query}, Length: {query_length}")

    print("\nDNS Record Type Analysis:")
    for record_type, count in record_type_counts.items():
        print(f"{record_type}: {count}")

    if unusual_patterns:
        print("\nUnusual Patterns Detected:")
        for record_type, count in unusual_patterns.items():
            print(f"{record_type}: {count} (higher than expected)")

    potential_tunneling = []
    for query, probabilities, entropy in char_freq_results:
        if entropy > 3.5: 
            potential_tunneling.append(query)

    print("\nPotential DNS Tunneling Detected:")
    for query in potential_tunneling:
        print(f"Domain: {query} with entropy: {entropy_results[dns_queries.index(query)]}")

    return domain_record_types, unusual_patterns

if __name__ == "__main__":

    pcapng_file = 'capturefile.pcapng'
    capture = read_pcapng(pcapng_file)

    domain_record_types, unusual_patterns = analyze_dns_signature(capture)
    print("*////////////////////////////////////////////////////////////*")
    if unusual_patterns:
        print("\nUnusual Patterns Detected:")
        for record_type, count in unusual_patterns.items():
            print(f"{record_type}: {count} (higher than expected)")
