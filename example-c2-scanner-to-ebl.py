#! /usr/bin/python
#
# Import yaml
import yaml
#Import urllib
import urllib.request
import urllib.error
# Import the JSON library
import json
#Import date libs
from datetime import datetime, timedelta
#Import sys - for files
import sys
#Import ipaddress
import ipaddress
#import pathlib
import pathlib
#from pathlib import pathlib,Path


API_CONFIG_FILE = 'example-c2-scanner-api-config.yaml'

with open(API_CONFIG_FILE, 'r') as config_file:
    config = yaml.load(config_file, Loader=yaml.SafeLoader)

c2url = config['example-c2-api']['apiurl']
apikey = config['example-c2-api']['apikey']
daysBack = config['example-c2-api']['daysBack']

c2ips = ""
c2domains = ""

#The URLs in the c2 beacon config is not reliable, could be anything
#Do not use it to block. Only the C2 key is verified for communication


from_date = datetime.now() - timedelta(days=daysBack)
from_date_str = from_date.strftime("%Y-%m-%d")
now_date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_ip_address(ip_string):
   try:
       ip_object = ipaddress.ip_address(ip_string)
       return True
   except ValueError:
       return False



##Extract C2 info depending on key type and becon config
def addC2data(c2, key=''):
    global c2ips
    global c2domains
    #From the API IPv6 is encoded in square brackets ([]), neither python ipaddress or PaloAlto EBLs want that, so we strip it
    key = key.strip("[]")
    if is_ip_address(key):
        c2ips += key + " # "+ c2["C2_last_confirmed"]+"\n"
    else:
        c2domains += key +" # "+ c2["C2_last_confirmed"]+"\n"

#
##Open files
fileips = open("c2ips.txt", "w")
filedomains = open("c2domains.txt", "w")
json_file = "c2data-json.txt"

data = None
#If there already is an json file
if pathlib.Path(json_file).is_file():
    #Check if it is not older than 55 min
    if not (datetime.fromtimestamp(pathlib.Path(json_file).stat().st_mtime) < (datetime.now()-timedelta(minutes=55))):
       print("We have fresh json cache data, using it")
       filejson = open("c2data-json.txt", "r")
       data = json.loads(filejson.read())

if not isinstance(data, dict):
    #If old or not exists , get a new one
    print("We don't have an fresh json cache file, downloading new data from API")
    headers = {'API-KEY': apikey}
    req = urllib.request.Request(c2url + "?last_seen_after="+from_date_str)
    req.add_header('API-KEY', apikey)
    try:
        jsonData = urllib.request.urlopen(req)
        data = json.load(jsonData)
        #print(data)
    except urllib.error.HTTPError as e:
        print('The C2-API returned error: ', e.code)
        sys.exit(1)
    except urllib.error.URLError as e:
        print('Could not reach  C2-API: ', e.reason)
        sys.exit(1)
    else:
        filejson = open("c2data-json.txt", "w")
        filejson.write(json.dumps(data, indent=4, separators=(",", ": ")))


#Iterate over the json data-set
if isinstance(data, dict):
    #Check single element or list
    if "whois" in data:
        addC2data(data)
    for key in data:
        addC2data(data[key],key)

##Write block data files
#IPs
print('#This file was generated ' + now_date_str + ' and  contains C2 IPs fetched from EXAMPLE C2-api with last_seen_after '+from_date_str, file=fileips)
print("#This data is verifed C2 beacons, should be safe to block" , file=fileips)
print("#Number of C2-IPs: " + str(len(c2ips.splitlines())), file=fileips)
fileips.write(c2ips)
print("#EOF\n", file=fileips)

#Domains
print('#This file was generated ' + now_date_str + ' and contains C2 domains fetched from EXAMPLE C2-api with last_seen_after '+from_date_str, file=filedomains)
print("#This data is verifed C2 beacons, should be safe to block" , file=filedomains)
print("#Number of C2-Domains: " + str(len(c2domains.splitlines())), file=filedomains)
filedomains.write(c2domains)
print("#EOF\n", file=filedomains)

##Return info
print ("Number of C2s: " + str(len(data)) + "\n")
print("Number of C2IPs: " + str(len(c2ips.splitlines())) + "\n")
#print(c2ips)
print("Number of C2domains: " + str(len(c2domains.splitlines())) + "\n")
#print(c2domains)


##Close files
fileips.close()
filedomains.close()

