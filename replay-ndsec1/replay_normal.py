#!/bin/python3

import os
import time
import requests
import urllib3
import argparse
from urllib.parse import urlparse
from scapy.all import *
from scapy.layers.http import *

### Disable SSL Warnings when using self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parser dos parametros
parser = argparse.ArgumentParser()
parser.add_argument("-pcap", "--pcap-file", dest='pcapfile', help="Arquivo PCAP.")
parser.add_argument("-dhost", "--dst-host", dest='dsthost', help="Host de destino para as requisicoes HTTP.")
args = parser.parse_args()
if len(sys.argv)<=2:
    parser.print_help(sys.stderr)
    print("\n")
    exit(1)


HOST = "http://"+args.dsthost

# Carrega PCAP
myreader = PcapReader(args.pcapfile)
http_requests = []

timestamp = ""
method = ""
path = ""
load = ""
prev_time = 0

while True:
    try:
        packet = myreader.read_packet()

        if HTTPRequest in packet:
            if packet['HTTP Request'].Method:
                path = packet['HTTP Request'].Path.decode("utf-8")
                file_type = os.path.splitext(path)[-1]
                if (file_type == ".php"):
                    #packet.show()
                    timestamp = packet.time
                    method = packet['HTTP Request'].Method.decode("utf-8")
                    path = packet['HTTP Request'].Path.decode("utf-8")
                    if packet['HTTP Request'].Method.decode("utf-8") == "POST":
                        load = packet['HTTP Request'].load.decode("utf-8")
                    else:
                        load = ""

                    print("{:>10}: {}".format("Timestamp", timestamp))
                    print("{:>10}: {}".format("Method", method))
                    print("{:>10}: {}".format("Path", path))
                    if load:
                        print("{:>10}: {}".format("Load", load))
                    print("\n")

                    sleep_time = packet.time - prev_time
                    prev_time = packet.time
                    http_requests.append([float(sleep_time), method, path, load])
    except EOFError:
        break


#s = requests.Session()
# --- TEST WITH SESSION ---
# s.get(HOST+"/DVWA/", allow_redirects=True)
#token = s.cookies.get("PHPSESSID")
# for cookie in s.cookies:
#     print (cookie.name, cookie.value)
#s.post(HOST+"/DVWA/login.php", data={"username": "admin", "password": "password", "user_token": token}, cookies=s.cookies, allow_redirects=True)
# --- END TEST WITH SESSION ---

http_requests[0][0] = 0
print("\n\nREQUESTS TIME INTERVALS:\n")
for r in http_requests:
    print(r)
    time.sleep(r[0])
    if (r[1]=="GET"):
        requests.get(HOST+r[2], allow_redirects=True)
    elif (r[1]=="POST" and r[2]=="/DVWA/login.php"):
        requests.post(HOST+r[2], data={"username": "admin", "password": "password"}, allow_redirects=True)
    elif (r[1]=="POST" and r[2]=="/DVWA/security.php"):
        requests.post(HOST+r[2], data={"security": "low"}, allow_redirects=True)

print("\n")



