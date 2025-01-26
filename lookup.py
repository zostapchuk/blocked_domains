import requests
import json
import urllib3
import ipaddress
import sys

domains = [ 'rutracker.org',
  'rutracker.cc'
  'instagram.com',
  'youtube.com',
  'tiktok.com',
  'linkedin.com',
]

baseDirectory = '/opt/blocked_domains'

class CIDRs:
    def __init__(self, lst):
        self.cidrs = []
        self.errors = []
        for _ in lst:
            try:
                self.cidrs.append(ipaddress.ip_network(_, strict=True))
            except ValueError as e:
                self.errors.append(str(e))
    def get_errors(self):
        return self.errors
    def get_ipv4_cidrs(self):
        return [c for c in self.cidrs if c.version == 4]
    def get_ipv6_cidrs(self):
        return [c for c in self.cidrs if c.version == 6]
    def get_cidrs(self):
        return self.get_ipv4_cidrs() + self.get_ipv6_cidrs()
    def collapse_ipv4_cidrs(self):
        return ipaddress.collapse_addresses(self.get_ipv4_cidrs())
    def collapse_ipv6_cidrs(self):
        return ipaddress.collapse_addresses(self.get_ipv6_cidrs())
    def summarize_cidrs(self):
        return [_ for _ in self.collapse_ipv4_cidrs()] + [_ for _ in self.collapse_ipv6_cidrs()]

session = requests.session()

zones = []
for domain in domains:
  response  = session.get(f'http://ip-api.com/json/{domain}')
  zone = response.json()['as'].split(' ')[0].split('AS')[1]
  if zone not in zones:
    zones.append(zone)

user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}
http = urllib3.PoolManager(10, headers=user_agent)
r = http.request('GET', 'https://bgp.tools/table.txt')
if r.status == 200:
  data = r.data.decode('utf-8')
  with open(f'{baseDirectory}/AStable.txt', 'w') as f:
    f.write(data)

networks = []
with open(f'{baseDirectory}/AStable.txt', 'r') as f:
  for line in f:
    as_net = line.rstrip().split(' ')[0]
    zone = line.rstrip().split(' ')[1]
    network = line.rstrip().split('/')[0]
    address = ipaddress.ip_address(network)
    if address.version == 4 and zone in zones:
      networks.append(as_net)

cidrs = CIDRs(set(networks))
with open(f'{baseDirectory}/subnet.txt', 'w') as f:
  for cidr in cidrs.summarize_cidrs():
    f.write(f'route {cidr} reject;\n')
