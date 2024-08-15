import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

dns_df = pd.read_csv('dns_captured.csv')

print(dns_df.head())       # Display the first 5 rows of the DataFrame
print(dns_df.describe())       # Generate descriptive statistics of df
print(dns_df.isnull().sum())   # Count the number of missing values in each column

sns.set(style='whitegrid')

plt.figure(figsize=(10, 6))        #analysis_Fig1 # Set the figure size to 10 inches width, 6 inches height
if dns_df['Query Type'].nunique() >= 1: #Checks if there is more than one unique query type in the DataFrame 
    sns.countplot(x='Query Type', hue='Query Type', data=dns_df, palette='viridis', legend=False) #Creates a count plot of the 'Query Type'
    plt.title('Distribution of DNS Query Types')
    plt.xlabel('Query Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)  #rotate the x-axis label  by 45 degrees. 
    plt.tight_layout()  #Adjusts the plot to ensure everything fits without overlapping the figure
    plt.show()

plt.figure(figsize=(10, 6))
if dns_df['Response Code'].nunique() >= 0:
    sns.countplot(x='Response Code', data=dns_df, palette='coolwarm')
    plt.title('Distribution of DNS Response Codes')
    plt.xlabel('Response Code')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Plot 3: Top 10 DNS Query Sources      
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

dns_df['Timestamp'] = pd.to_datetime(dns_df['Timestamp']) 
dns_df.set_index('Timestamp', inplace=True)
daily_counts = dns_df.resample('D').size()
plt.figure(figsize=(12, 6))
daily_counts.plot(color='blue')
plt.title('DNS Query Count Over Time')
plt.xlabel('Date')
plt.ylabel('Count')
plt.tight_layout()
plt.show()


plt.figure(figsize=(10, 6))  
if dns_df['Query Class'].nunique() > 1:
    sns.countplot(x='Query Class', data=dns_df, palette='cubehelix')
    plt.title('Distribution of DNS Query Classes')
    plt.xlabel('Query Class')
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

plt.figure(figsize=(10, 8))
dns_types_codes = dns_df.groupby(['Query Type', 'Response Code']).size().unstack(fill_value=0)
if not dns_types_codes.empty:
   sns.heatmap(dns_types_codes, cmap='YlGnBu', annot=True, fmt='d')
   plt.title('Heatmap of DNS Query Types and Response Codes')
   plt.xlabel('Query Types')
   plt.ylabel('Response Codes')
   plt.tight_layout()
   plt.show()

# Plot 10: Pairplot of DNS Features              
sns.pairplot(dns_df[['Query Type', 'Query Class', 'Query Length']], palette='dark')
plt.suptitle('Pairplot of DNS Features', y=1.02)
plt.tight_layout()
plt.show()
