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

basedir = f'/opt/blocked_domains'
Path(basedir).mkdir(parents=True, exist_ok=True)

rublacklist_url = 'https://reestr.rublacklist.net/api/v3'
stats = 'statistics'
domains = 'domains'
ips = 'ips'
dpi = 'dpi'

def whipe_file(file):
  f = open(file, 'w')
  f.close()

def get_as_zones_by_domain(zonesfile, domains):
  whipe_file(zonesfile)
  for domain in domains:
    response  = session.get(f'http://ip-api.com/json/{domain}')
    if response.json()['status'] == 'fail':
      logging.warning(f'{domain} NOT RESOLVED with http://ip-api.com/json')
    else:
      zone = response.json()['as'].split(' ')[0]
      logging.info(f'{domain} resolved as zone {zone}')
      if zone not in zones:
        zones.append(zone)
        with open(zonesfile, 'a') as f:
          f.write(f'{zone}\n')


def get_cidr_by_as(zone, dir):
  user_agent = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}
  http = urllib3.PoolManager(10, headers=user_agent)
  url = f'https://bgp.he.net/{zone}'
  r = http.request('GET', url)
  if r.status == 200:
    data = r.data.decode('utf-8')
    ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', data)
    with open(f'{basedir}/{dir}/{zone}.txt', 'w') as f:
      for address in ip:
        f.write(f'{address}\n')
      logging.info(f'Get CIDRs for zone {zone} success, file: {basedir}/{dir}/{zone}.txt')
  else:
    logging.warning(f'Get CIDRs for zone {zone} failure')

session = requests.session()

domains = []
zones = []

if args.c:
  dir = 'custom'
  zonesfile = f'{basedir}/{dir}/zones.txt'
  Path(f'{basedir}/{dir}').mkdir(parents=True, exist_ok=True)
  domains = []
  zones = []
  logging.info('Working with custom file choosen')

  with open(f'{basedir}/list.txt', 'r') as f:
    for line in f:
      domains.append(line.rstrip())
  logging.info(f'Domains List: {domains}')

else:
  dir = 'auto'
  zonesfile = f'{basedir}/{dir}/zones.txt'
  Path(f'{basedir}/{dir}').mkdir(parents=True, exist_ok=True)
  domains = []
  zones = []
  logging.info('Working with data from api choosen')

  response = session.get(f'{rublacklist_url}/{dpi}')
  for i in response.json():
    for j in i['domains']:
      domains.append(j)
      logging.info(f'Found DPI blocked domain: {j}')

if args.r:
  logging.info('Reading zones.txt file')
  with open(zonesfile, 'r') as f:
    for line in f:
      zone = line.rstrip()
      zones.append(zone)
      logging.info(f'Found {zone} in {basedir}/{dir}')
else:
  logging.info('Reading zones from api')
  get_as_zones_by_domain(zonesfile, domains)

for zone in zones:
  try:
    get_cidr_by_as(zone, dir)
  except:
    raise Exception

