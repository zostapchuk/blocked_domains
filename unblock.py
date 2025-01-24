import requests
import json
import ipaddress
import os
import time
import argparse
import urllib3
import re

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--read', action=argparse.BooleanOptionalAction)
args = parser.parse_args()

ip_api_url = 'http://ip-api.com/json'
bgp = 'https://bgp.he.net'
rublacklist_url = 'https://reestr.rublacklist.net/api/v3'
stats = 'statistics'
domains = 'domains'
ips = 'ips'
dpi = 'dpi'

blocked_domains = []
failure_domains = []
blocked_zones = []

session = requests.session()

if args.read:
  with open('/opt/blacklist/blocked_domains.txt', 'r') as f:
    for line in f:
      blocked_domains.append(line.rstrip())
  with open('/opt/blacklist/blocked_zones.txt', 'r') as f:
    for line in f:
      blocked_zones.append(line.rstrip())
else:
  response = session.get(f'{rublacklist_url}/{dpi}')
  for i in response.json():
    for j in i['domains']:
      blocked_domains.append(j)

  with open('/opt/blacklist/blocked_domains.txt', 'w') as f:
    for domain in blocked_domains:
      f.write(f'{domain}\n')

  for domain in blocked_domains:
    response  = session.get(f'{ip_api_url}/{domain}')
    if response.json()['status'] == 'fail':
      failure_domains.append(domain)
    else:
      azone = response.json()['as'].split(' ')[0]
      if azone not in blocked_zones:
        blocked_zones.append(azone)

  with open('/opt/blacklist/blocked_zones.txt', 'w') as f:
    for azone in blocked_zones:
      f.write(f'{azone}\n')

user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}
http = urllib3.PoolManager(10, headers=user_agent)
for azone in blocked_zones:
  url = f'{bgp}/{azone}'
  r = http.request('GET', url)
  if r.status == 200:
    data = r.data.decode('utf-8')
    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', data)
    with open(f'/opt/blacklist/blocked_{azone}.txt', 'w') as f:
      for address in ip:
        f.write(f'{address}\n')
