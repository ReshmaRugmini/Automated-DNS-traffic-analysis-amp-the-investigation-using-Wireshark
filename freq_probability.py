import pyshark
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def extract_domain_subdomain(domain):
    """
    Extract the domain and subdomain from a full domain name.
    """
    parts = domain.split('.')
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2])
        domain = '.'.join(parts[-2:])
    else:
        subdomain = ''
        domain = '.'.join(parts)
    return domain, subdomain

def char_frequency_probability(domain):
    """
    Calculate the probability of each character in the domain.
    """
    domain = domain.lower()
    length = len(domain)
    freq = Counter(domain)
    probabilities = {char: count / length for char, count in freq.items()}
    return probabilities

def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    return capture

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
    domain_subdomain_data = []

    for query in dns_queries:
        domain, subdomain = extract_domain_subdomain(query)
        probabilities = char_frequency_probability(query)
        domain_lengths.append(len(query))
        domain_lengths.append(len(query))
        domain_subdomain_data.append({'Domain': domain, 'Subdomain': subdomain, 'Full Query': query})
        for char, prob in probabilities.items():
            char_freq_data.append({'Domain': query, 'Character': char, 'Probability': prob})

    return char_freq_data, domain_lengths, domain_subdomain_data

def plot_character_frequency_distribution(df_char_freq):
    """
    Plot character frequency distribution.
    """
    plt.figure(figsize=(10, 6))
    sns.histplot(df_char_freq['Probability'], kde=True, bins=30)
    plt.title('Character Frequency Distribution')
    plt.xlabel('Probability')
    plt.ylabel('Frequency')
    plt.show()

def plot_domain_length_distribution(domain_lengths):
    """
    Plot domain length distribution.
    """
    plt.figure(figsize=(10, 6))
    sns.histplot(domain_lengths, kde=True, bins=10)
    plt.title('Domain Length Distribution')
    plt.xlabel('Length')
    plt.ylabel('Frequency')
    plt.show()

def plot_character_frequency_heatmap(df_char_freq):
    """
    Plot character frequency heatmap.
    """
    char_matrix = df_char_freq.pivot_table(index='Domain', columns='Character', values='Probability', fill_value=0)
    plt.figure(figsize=(12, 8))
    sns.heatmap(char_matrix, cmap='viridis', cbar=True, linewidths=0.5)
    plt.title('Character Frequency Heatmap')
    plt.show()

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
    plt.show()
    
def plot_domain_subdomain_distribution(df_domain_subdomain):
    """
    Plot distribution of domains and subdomains.
    """
    plt.figure(figsize=(14, 12))
    sns.countplot(y='Domain', data=df_domain_subdomain, order=df_domain_subdomain['Domain'].value_counts().index)
    plt.title('Domain Distribution')
    plt.xlabel('Count')
    plt.ylabel('Domain')
    plt.show()

    plt.figure(figsize=(14, 12))
    sns.countplot(y='Subdomain', data=df_domain_subdomain, order=df_domain_subdomain['Subdomain'].value_counts().index)
    plt.title('Subdomain Distribution')
    plt.xlabel('Count')
    plt.ylabel('Subdomain')
    plt.show()


if __name__ == "__main__":
    # Read DNS traffic from a pcapng file
    pcapng_file = 'capturefile.pcapng'
    capture = read_pcapng(pcapng_file)

    # Analyze character frequency probabilities
    char_freq_data, domain_lengths, domain_subdomain_data = analyze_dns_char_freq(capture)

    # Convert analysis results to DataFrame
    df_char_freq = pd.DataFrame(char_freq_data)
    df_domain_subdomain = pd.DataFrame(domain_subdomain_data)
    
    # Generate and display plots
    plot_character_frequency_distribution(df_char_freq)
    plot_domain_length_distribution(domain_lengths)
    plot_character_frequency_heatmap(df_char_freq)
    plot_top_n_frequent_characters(df_char_freq)
    plot_domain_subdomain_distribution(df_domain_subdomain)