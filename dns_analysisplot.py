import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import os
from collections import Counter
import math
import datetime
import asyncio

def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    # Create an event loop for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.FileCapture(file_path, display_filter='dns', eventloop=loop)
    packets = []
    for packet in capture:
        packets.append(packet)
    capture.close()
    return packets

def analyze_dns_query_length(capture):
    """
    Analyze DNS query lengths from the captured packets.
    """
    dns_queries = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name)

    query_length_results = []
    for query in dns_queries:
        query_length = len(query)
        query_length_results.append((query, query_length))
        print(f"Domain: {query}, Length: {query_length}")

    return query_length_results


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

    # Calculate total number of queries
    total_queries = len(dns_record_types)

    # Calculate expected frequency (e.g., based on typical DNS traffic)
    expected_frequency = total_queries / len(record_type_counts)

    # Identify unusual patterns (record types with frequency significantly different from expected)
    unusual_patterns = {}
    for record_type, count in record_type_counts.items():
        if count > expected_frequency * 1.5:  # Adjust the threshold as per your analysis
            unusual_patterns[record_type] = count

    print("DNS Record Type Counts:")
    for record_type, count in record_type_counts.items():
        print(f"{record_type}: {count}")

    return domain_record_types, record_type_counts, unusual_patterns

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

    # Ensure the directory exists
    os.makedirs('dashboard_app/static/plots', exist_ok=True)

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
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/character_frequency_distribution.png')
    plt.close()

    # 2. Entropy Distribution
    plt.figure(figsize=(12, 6))
    plt.subplot(1, 3, 2)
    sns.histplot(entropy_results, kde=True, bins=20)
    plt.title('Entropy Distribution')
    plt.xlabel('Entropy')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/entropy_distribution.png')
    plt.close()

    # 3. DNS Query Length Distribution
    query_lengths = [length for query, length in query_length_results]
    
    plt.figure(figsize=(12, 6))
    plt.subplot(1, 3, 3)
    sns.histplot(query_lengths, kde=True, bins=20)
    plt.title('DNS Query Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_length_distribution.png')
    plt.close()

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

def analyze_dns_traffic_volume(capture):
    """
    Analyze DNS traffic volume over time.
    """
    timestamps = []
    dns_queries = []

    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name.lower())
            timestamps.append(datetime.datetime.fromtimestamp(float(packet.sniff_timestamp)))

    return timestamps, dns_queries

def plot_traffic_volume(timestamps):
    """
    Plot DNS traffic volume over time.
    """
    time_counts = Counter(timestamps)
    times = list(time_counts.keys())
    counts = list(time_counts.values())

    plt.figure(figsize=(12, 6))
    plt.plot(times, counts, marker='o')
    plt.xlabel('Time')
    plt.ylabel('DNS Query Volume')
    plt.title('DNS Traffic Volume Over Time')
    plt.grid(True)
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig('dashboard_app/static/plots/dns_traffic_volume.png')
    plt.close()

def analyze_time_intervals(timestamps):
    """
    Analyze time intervals between DNS queries.
    """
    intervals = []
    for i in range(1, len(timestamps)):
        interval = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(interval)

    return intervals

def plot_time_intervals(intervals):
    """
    Plot the distribution of time intervals between DNS queries.
    """
    plt.figure(figsize=(12, 6))
    plt.hist(intervals, bins=50, alpha=0.75)
    plt.xlabel('Time Interval (seconds)')
    plt.ylabel('Frequency')
    plt.title('Distribution of Time Intervals Between DNS Queries')
    plt.grid(True)
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig('dashboard_app/static/plots/dns_time_intervals.png')
    plt.close()

def char_frequency_probability(domain):
    """
    Calculate the probability of each character in the domain.
    """
    domain = domain.lower()
    length = len(domain)
    freq = Counter(domain)
    probabilities = {char: count / length for char, count in freq.items()}
    return probabilities


def analyze_dns_char_freq(capture):
    """
    Analyze character frequency probabilities from the captured DNS packets.
    """
    dns_queries = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name.lower())

    char_freq_data = []
    domain_lengths = []

    for query in dns_queries:
        probabilities = char_frequency_probability(query)
        domain_lengths.append(len(query))
        for char, prob in probabilities.items():
            char_freq_data.append({'Domain': query, 'Character': char, 'Probability': prob})

    return char_freq_data, domain_lengths

def plot_character_frequency_distribution(df_char_freq):
    """
    Plot character frequency distribution.
    """
    plt.figure(figsize=(10, 6))
    sns.histplot(df_char_freq['Probability'], kde=True, bins=30)
    plt.title('Character Frequency Distribution')
    plt.xlabel('Probability')
    plt.ylabel('Frequency')
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig('dashboard_app/static/plots/char_frequency_distribution.png')
    plt.close()

def plot_domain_length_distribution(domain_lengths):
    """
    Plot domain length distribution.
    """
    plt.figure(figsize=(10, 6))
    sns.histplot(domain_lengths, kde=True, bins=30)
    plt.title('Domain Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig('dashboard_app/static/plots/domain_length_distribution.png')
    plt.close()

def plot_character_frequency_heatmap(df_char_freq):
    """
    Plot character frequency heatmap.
    """
    char_matrix = df_char_freq.pivot_table(index='Domain', columns='Character', values='Probability', fill_value=0)
    plt.figure(figsize=(12, 8))
    sns.heatmap(char_matrix, cmap='viridis', cbar=True, linewidths=0.5)
    plt.title('Character Frequency Heatmap')
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig('dashboard_app/static/plots/char_frequency_heatmap.png')
    plt.close()

def plot_top_n_frequent_characters(df_char_freq, n=10):
    """
    Plot top N most frequent characters.
    """
    top_chars = df_char_freq.groupby('Character')['Probability'].mean().sort_values(ascending=False).head(n)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_chars.index, y=top_chars.values)
    plt.title(f'Top {n} Most Frequent Characters')
    plt.xlabel('Character')
    plt.ylabel('Average Probability')
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    plt.savefig(f'dashboard_app/static/plots/top_{n}_frequent_characters.png')
    plt.close()

def shannon_entropy(domain):
    """
    Calculate the Shannon entropy of a domain.
    """
    domain = domain.lower()
    freq = Counter(domain)
    entropy = -sum((count / len(domain)) * math.log2(count / len(domain)) for count in freq.values())
    return entropy


def analyze_dns_entropy(capture):
    """
    Analyze DNS entropy from the captured packets.
    """
    dns_queries = []
    for packet in capture:
        if hasattr(packet.dns, 'qry_name'):
            dns_queries.append(packet.dns.qry_name)

    entropy_results = []
    high_entropy = []

    for query in dns_queries:
        entropy = shannon_entropy(query)
        entropy_results.append((query, entropy))
        if entropy > 3.5:
            high_entropy.append((query, entropy))

    return entropy_results, high_entropy

def plot(capture):
    # Ensure the directory exists
    os.makedirs('dashboard_app/static/plots', exist_ok=True)
    
    dns_df = pd.read_csv('dns_captured.csv')

    print(dns_df.head())
    print(dns_df.describe())
    print(dns_df.isnull().sum())

    sns.set(style='whitegrid')

    plt.figure(figsize=(10, 6))
    if dns_df['Query Type'].nunique() > 1:
        sns.countplot(x='Query Type', data=dns_df, palette='viridis')
        plt.title('Distribution of DNS Query Types')
        plt.xlabel('Query Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('dashboard_app/static/plots/dns_query_types.png')
        plt.close()

    plt.figure(figsize=(10, 6))
    if dns_df['Response Code'].nunique() > 1:
        sns.countplot(x='Response Code', data=dns_df, palette='coolwarm')
        plt.title('Distribution of DNS Response Codes')
        plt.xlabel('Response Code')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('dashboard_app/static/plots/dns_response_codes.png')
        plt.close()

    # Plot 3: Top 10 DNS Query Sources
    top_sources = dns_df['Source IP'].value_counts().head(10)
    plt.figure(figsize=(12, 8))
    sns.barplot(x=top_sources.index, y=top_sources.values, palette='plasma')
    plt.title('Top 10 DNS Query Sources')
    plt.xlabel('Source IP')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_sources.png')
    plt.close()

    top_destinations = dns_df['Destination IP'].value_counts().head(10)
    plt.figure(figsize=(12, 8))
    sns.barplot(x=top_destinations.index, y=top_destinations.values, palette='inferno')
    plt.title('Top 10 DNS Query Destinations')
    plt.xlabel('Destination IP')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_destinations.png')
    plt.close()

    dns_df['Timestamp'] = pd.to_datetime(dns_df['Timestamp'])
    dns_df.set_index('Timestamp', inplace=True)
    daily_counts = dns_df.resample('D').size()
    plt.figure(figsize=(12, 6))
    daily_counts.plot(color='blue')
    plt.title('DNS Query Count Over Time')
    plt.xlabel('Date')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_over_time.png')
    plt.close()

    plt.figure(figsize=(10, 6))
    if dns_df['Query Class'].nunique() > 1:
        sns.countplot(x='Query Class', data=dns_df, palette='cubehelix')
        plt.title('Distribution of DNS Query Classes')
        plt.xlabel('Query Class')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('dashboard_app/static/plots/dns_query_classes.png')
        plt.close()

    plt.figure(figsize=(12, 8))
    sns.scatterplot(x='Source IP', y='Destination IP', data=dns_df, alpha=0.5)
    plt.title('Distribution of DNS Queries by Source and Destination')
    plt.xlabel('Source IP')
    plt.ylabel('Destination IP')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_source_destination.png')
    plt.close()

    dns_df['Query Length'] = dns_df['Query'].apply(len)
    plt.figure(figsize=(10, 6))
    sns.histplot(x='Query Length', data=dns_df, bins=20, kde=True, color='green')
    plt.title('Distribution of DNS Query Length')
    plt.xlabel('Query Length')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_length.png')
    plt.close()

    plt.figure(figsize=(10, 8))
    dns_types_codes = dns_df.groupby(['Query Type', 'Response Code']).size().unstack(fill_value=0)
    if not dns_types_codes.empty:
        sns.heatmap(dns_types_codes, cmap='YlGnBu', annot=True, fmt='d')
        plt.title('Heatmap of DNS Query Types and Response Codes')
        plt.xlabel('Response Code')
        plt.ylabel('Query Type')
        plt.tight_layout()
        plt.savefig('dashboard_app/static/plots/dns_query_type_response_code_heatmap.png')
        plt.close()

    # Plot 10: Pairplot of DNS Features
    sns.pairplot(dns_df[['Query Type', 'Query Class', 'Query Length']], palette='dark')
    plt.suptitle('Pairplot of DNS Features', y=1.02)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_features_pairplot.png')
    plt.close()

    os.makedirs('dashboard_app/static/plots', exist_ok=True)

    # Read DNS traffic from a pcapng file
    # capture = read_pcapng(pcapng_file)

    # Analyze DNS query lengths
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
    plt.savefig('dashboard_app/static/plots/dns_query_lengths_bar.png')
    plt.close()

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
    plt.savefig('dashboard_app/static/plots/dns_query_lengths_pie.png')
    plt.close()

    # Histogram: Distribution of query lengths
    plt.figure(figsize=(10, 6))
    sns.histplot(lengths, bins=20, kde=True, color='blue')
    plt.title('Distribution of Query Lengths')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_lengths_histogram.png')
    plt.close()

    # Boxplot: Summary of query lengths
    plt.figure(figsize=(10, 6))
    sns.boxplot(x=lengths, palette='viridis')
    plt.title('Boxplot of Query Lengths')
    plt.xlabel('Length')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_query_lengths_boxplot.png')
    plt.close()

    domain_record_types, record_type_counts, unusual_patterns = analyze_dns_record_types(capture)

    for domain, record_type in domain_record_types.items():
        print(f"Domain: {domain}, Record Type: {record_type}")

    if unusual_patterns:
        print("\nUnusual Patterns Detected:")
        for record_type, count in unusual_patterns.items():
            print(f"{record_type}: {count} (higher than expected)")

    # Prepare data for plotting
    record_types = list(record_type_counts.keys())
    counts = list(record_type_counts.values())

    # Bar Chart: Count of each DNS record type
    plt.figure(figsize=(14, 7))
    sns.barplot(x=record_types, y=counts, palette='viridis')
    plt.title('Count of Each DNS Record Type')
    plt.xlabel('Record Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_record_type_counts.png')
    plt.close()

    # Pie Chart: Proportion of different DNS record types
    colors = sns.color_palette('viridis', len(record_types))
    plt.figure(figsize=(8, 8))
    plt.pie(counts, labels=record_types, colors=colors, autopct='%1.1f%%',
            shadow=True, startangle=140)
    plt.title('Proportion of Different DNS Record Types')
    plt.axis('equal')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/dns_record_type_proportions.png')
    plt.close()

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
        plt.savefig('dashboard_app/static/plots/dns_unusual_patterns.png')
        plt.close()

    domain_record_types, unusual_patterns = analyze_dns_signature(capture)
    print("*////////////////////////////////////////////////////////////*")
    if unusual_patterns:
        print("\nUnusual Patterns Detected:")
        for record_type, count in unusual_patterns.items():
            print(f"{record_type}: {count} (higher than expected)")

    timestamps, dns_queries = analyze_dns_traffic_volume(capture)
    plot_traffic_volume(timestamps)

    # Analyze time intervals between DNS queries
    intervals = analyze_time_intervals(timestamps)
    plot_time_intervals(intervals)

    char_freq_data, domain_lengths = analyze_dns_char_freq(capture)

    # Convert analysis results to DataFrame
    df_char_freq = pd.DataFrame(char_freq_data)

    # Generate and save plots
    plot_character_frequency_distribution(df_char_freq)
    plot_domain_length_distribution(domain_lengths)
    plot_character_frequency_heatmap(df_char_freq)
    plot_top_n_frequent_characters(df_char_freq)

    entropy_results, high_entropy = analyze_dns_entropy(capture)

    for domain, entropy in entropy_results:
        print(f"Domain: {domain}, Entropy: {entropy:.2f}")
    for domain, entropy in high_entropy:
        print(f"High entropy domain detected: {domain} with entropy {entropy:.2f}")
    
    print("//////////////////////////////////////")
    print(len(entropy_results))
    print(len(high_entropy))
    print("//////////////////////////////////////")

    domains = [result[0] for result in entropy_results]
    entropies = [result[1] for result in entropy_results]
    high_entropy_domains = [result[0] for result in high_entropy]
    high_entropies = [result[1] for result in high_entropy]

    os.makedirs('dashboard_app/static/plots', exist_ok=True)

    plt.figure(figsize=(14, 7))
    sns.barplot(x=domains, y=entropies, palette='viridis')
    plt.title('Entropy of Each Domain')
    plt.xlabel('Domain')
    plt.ylabel('Entropy')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/entropy_of_each_domain.png')
    plt.close()

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
    plt.savefig('dashboard_app/static/plots/proportion_of_high_entropy_domains.png')
    plt.close()

    # Histogram: Distribution of entropy values
    plt.figure(figsize=(10, 6))
    sns.histplot(entropies, bins=20, kde=True, color='blue')
    plt.title('Distribution of Entropy Values')
    plt.xlabel('Entropy')
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig('dashboard_app/static/plots/distribution_of_entropy_values.png')
    plt.close()



    

