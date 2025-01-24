import requests
import json
import ipaddress
import os
import sys
import time
import argparse
import urllib3
import re
import logging
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('-r', help='read files instead of asking APIs', action=argparse.BooleanOptionalAction)
parser.add_argument('-c', help='use custom domains file - list.txt', action=argparse.BooleanOptionalAction)
parser.add_argument('-l', help='if set, log to unblock.log instead of stdout', action=argparse.BooleanOptionalAction)
args = parser.parse_args()

if args.l:
  logging.basicConfig(level=logging.INFO, filename='unblock.log', filemode='w', format='%(asctime)s %(levelname)s %(message)s')
else:
  logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

baseDir = f'/opt/blocked_domains'
resultDir = 'results'
Path(baseDir).mkdir(parents=True, exist_ok=True)
Path(resultDir).mkdir(parents=True, exist_ok=True)

ip_api_url = 'http://ip-api.com/json'
rublacklist_url = 'https://reestr.rublacklist.net/api/v3'
stats = 'statistics'
domains = 'domains'
ips = 'ips'
dpi = 'dpi'

def get_cidr_by_as(zone, dir):
  user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}
  http = urllib3.PoolManager(10, headers=user_agent)
  url = f'https://bgp.he.net/{zone}'
  r = http.request('GET', url)
  if r.status == 200:
    data = r.data.decode('utf-8')
    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', data)
    with open(f'{baseDir}/{dir}/{zone}.txt', 'w') as f:
      for address in ip:
        f.write(f'{address}\n')
      logging.info(f'Get CIDRs for zone {zone} success, file: {baseDir}/{resultDir}/{zone}.txt')
  else:
    logging.warning(f'Get CIDRs for zone {zone} failure')

blocked_domains = []
failure_domains = []
blocked_zones = []
custom_domains = []
custom_blocked_zones = []

session = requests.session()

if args.c and not args.r:
  dir = 'custom'
  Path(f'{baseDir}/{dir}').mkdir(parents=True, exist_ok=True)
  domains = []
  zones = []
  logging.info('Working with custom file choosen')
  with open(f'{baseDir}/list.txt', 'r') as f:
    for line in f:
      domains.append(line.rstrip())
  logging.info(f'Domains List: {domains}')

  for domain in domains:
    response  = session.get(f'{ip_api_url}/{domain}')
    if response.json()['status'] == 'fail':
      logging.warning(f'{domain} NOT RESOLVED with http://ip-api.com/json')
    else:
      zone = response.json()['as'].split(' ')[0]
      logging.info(f'{domain} resolved as zone {zone}')
      if zone not in zones:
        zones.append(zone)

  for zone in zones:
    try:
      get_cidr_by_as(zone, dir)
    except:
      raise Exception

else:
  if args.r:
    logging.info('Working with rublacklist as a source')
    with open(f'{baseDir}/{resultDir}/blocked_domains.txt', 'r') as f:
      for line in f:
        blocked_domains.append(line.rstrip())
    with open(f'{baseDir}/{resultDir}/blocked_zones.txt', 'r') as f:
      for line in f:
        blocked_zones.append(line.rstrip())
  else:
    response = session.get(f'{rublacklist_url}/{dpi}')
    for i in response.json():
      for j in i['domains']:
        blocked_domains.append(j)

    with open(f'{baseDir}/{resultDir}/blocked_domains.txt', 'w') as f:
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

    with open(f'{baseDir}/{resultDir}/blocked_zones.txt', 'w') as f:
      for azone in blocked_zones:
        f.write(f'{azone}\n')
