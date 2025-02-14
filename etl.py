# import librarys
import pandas as pd
#from matplotlib import pyplot as plt
#import plotly.graph_objects as go
#import folium
#from folium import Marker
import os
import re
#import seaborn as sns
import ipaddress


def extract_ip(ip):
    return ip.split('.')[0]

def device_identifier(user_agent):
    user_agent = user_agent.strip()
    for device in devices:
        matching = re.findall(device, user_agent, re.IGNORECASE)
        if matching:
            return matching[0]
    return 'Unknown Device'

devices = [
    r'Windows',
    r'Macintosh',
    r'Linux',
    r'iPhone',
    r'iPod',
    r'iPad',
    r'Android'
]

df = pd.read_csv("cybersecurity_attacks.csv")
print(df.head(1).T)

df.rename(columns={'Timestamp':'Datetime'}, inplace=True)
df['Datetime'] = df['Datetime'].apply(lambda x: pd.to_datetime(x))
df['year'] = df['Datetime'].dt.year
df['month'] = df['Datetime'].dt.month
df['day'] = df['Datetime'].dt.day
df['dayofweek'] = df['Datetime'].dt.dayofweek
df['hour'] = df['Datetime'].dt.hour
df['minute'] = df['Datetime'].dt.minute
df['second'] = df['Datetime'].dt.second

df['Targeted Device'] = df['Device Information'].apply(device_identifier)
df['Targeted Device'].unique()

missing_columns = ['Alerts/Warnings', 'IDS/IPS Alerts', 'Malware Indicators', 'Firewall Logs', 'Proxy Information']

# fill missing values 
fillvalaues = ['None', 'No Data', 'No Detected', 'No Data', 'No Proxy Data']
for i in range(len(fillvalaues)):
    df.fillna({missing_columns[i]: fillvalaues[i]}, inplace=True)

df['Source IP Type'] = df['Source IP Address'].apply(lambda x: "Private" if ipaddress.ip_address(x).is_private else "Public")
df['Destiantion IP Type'] = df['Destination IP Address'].apply(lambda x: "Private" if ipaddress.ip_address(x).is_private else "Public")

df['Source First IP'] = df['Source IP Address'].apply(extract_ip)
df['Destination First IP'] = df['Destination IP Address'].apply(extract_ip)
df['Source First IP'] = df['Source First IP'].astype(int)
df['Destination First IP'] = df['Destination First IP'].astype(int)

#print(df.info())
#print(df)
# Threat Trend
print('----------------------------------------------------------')
print(df.head(1).T)
