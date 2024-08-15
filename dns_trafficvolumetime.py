import pyshark
from collections import Counter
import datetime
import matplotlib.pyplot as plt

def read_pcapng(file_path):
    """
    Read DNS packets from a pcapng file.
    """
    capture = pyshark.FileCapture(file_path, display_filter='dns')
    return capture

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
    plt.show()

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
    plt.show()

if __name__ == "__main__":
    # Read DNS traffic from a pcapng file
    pcapng_file = 'capturefile.pcapng'
    capture = read_pcapng(pcapng_file)

    # Analyze DNS traffic volume over time
    timestamps, dns_queries = analyze_dns_traffic_volume(capture)
    plot_traffic_volume(timestamps)

    # Analyze time intervals between DNS queries
    intervals = analyze_time_intervals(timestamps)
    plot_time_intervals(intervals)