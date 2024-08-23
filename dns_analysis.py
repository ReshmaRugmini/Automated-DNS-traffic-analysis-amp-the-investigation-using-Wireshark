import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

dns_df = pd.read_csv('dns_captured.csv')

print(dns_df.head())       
print(dns_df.describe())      
print(dns_df.isnull().sum())  

sns.set(style='whitegrid')

#Plot: Top 10 DNS Query Sources      
top_sources = dns_df['Source IP'].value_counts().head(10)
plt.figure(figsize=(12, 8))
sns.barplot(x=top_sources.index, y=top_sources.values, palette='plasma')
plt.title('Top 10 DNS Query Sources')
plt.xlabel('Source IP')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

top_destinations = dns_df['Destination IP'].value_counts().head(10)  
plt.figure(figsize=(12, 8))
sns.barplot(x=top_destinations.index, y=top_destinations.values, palette='inferno')
plt.title('Top 10 DNS Query Destinations')
plt.xlabel('Destination IP')
plt.ylabel('Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


plt.figure(figsize=(12, 8)) 
sns.scatterplot(x='Source IP', y='Destination IP', data=dns_df, alpha=0.5)
plt.title('Distribution of DNS Queries by Source and Destination')
plt.xlabel('Source IP')
plt.ylabel('Destination IP')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

dns_df['Query Length'] = dns_df['Query'].apply(len)       
plt.figure(figsize=(10, 6))
sns.histplot(x='Query Length', data=dns_df, bins=20, kde=True, color='green')
plt.title('Distribution of DNS Query Length')
plt.xlabel('Query Length')
plt.ylabel('Count')
plt.tight_layout()
plt.show()

