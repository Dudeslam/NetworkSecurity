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


from socket import *
import threading
from struct import *

#create streaming socket
try:
    s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])



def recv_pack():
	packet = s.recvfrom(65565)
	
	#packet string from tuple
	packet = packet[0]
	
	#take first 20 characters for the ip header
	ip_header = packet[0:20]
	
	#now unpack them :)
	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	
	iph_length = ihl * 4
	
	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8])
	d_addr = socket.inet_ntoa(iph[9])
	
	print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + 
    'Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
	
	tcp_header = packet[iph_length:iph_length+20]
	
	#now unpack them :)
	tcph = unpack('!HHLLBBHHH' , tcp_header)
	
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4
	
	print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + 
    ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
	
	h_size = iph_length + tcph_length * 4
	data_size = len(packet) - h_size
	
	#get data from the packet
	data = packet[h_size:]
	
	print ('Data : ' + data)



def main():
    while True:
        recv_pack()


if __name__ == "__main__":
    main()
