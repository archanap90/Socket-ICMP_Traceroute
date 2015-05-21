# -*- coding: cp1252 -*-
from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def checksum(str):
# In this function we make the checksum of our packet
    calChksum = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(str), 2):
        w = ord(str[i]) + (ord(str[i+1]) << 8 )
        calChksum = calChksum + w
     
    calChksum = (calChksum>>16) + (calChksum & 0xffff);  # Add high 16 bits to low 16 bits
    calChksum = calChksum + (calChksum >> 16);          # Add carry from above (if any)
     
    #complement and mask to 4 byte short
    calChksum = ~calChksum & 0xffff
     
    return calChksum
  
# hint: see icmpPing lab
def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        myChksum = 0

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChksum, id, 1)
        data = struct.pack("d", time.time()) + data

        # Calculate the checksum on the data and the dummy header.
        myChksum = checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(myChksum), id, 1)

# Make the header in a similar way to the ping exercise.
# Append checksum to the header.
# Don’t send the packet yet , just return the final packet in this function.
# So the function ending should look like this
        packet = header + data
        return packet

def get_route(hostname):
        timeLeft = TIMEOUT
        for ttl in xrange(1,MAX_HOPS):
                for tries in xrange(TRIES):
                        destAddr = gethostbyname(hostname)
#Fill in start# Make a raw socket named mySocket
                        mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
 #Fill in end
                        mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
                        mySocket.settimeout(TIMEOUT)
                        try:
                                d = build_packet()
                                mySocket.sendto(d, (hostname, 0))
                                t= time.time()
                                startedSelect = time.time()
                                whatReady = select.select([mySocket], [], [], timeLeft)
                                howLongInSelect = (time.time() - startedSelect)
                                if whatReady[0] == []: # Timeout
                                        print " * * * Request timed out."
                                recvPacket, addr = mySocket.recvfrom(1024)
                                timeReceived = time.time()
                                timeLeft = timeLeft - howLongInSelect
                                if timeLeft <= 0:
                                        print " * * * Request timed out."
                        except timeout:
                                        continue
                        else:
                                #Fill in start
                                # Fetch the icmp type from the IP packet
                                type = recvPacket.getlayer(ICMP).type
                                #Fill in end
                                if type == 11:
                                        bytes = struct.calcsize("d")
                                        timeSent = struct.unpack("d", recvPacket[28:28 +
bytes])[0]
                                        print " %d rtt=%.0f ms %s" %(ttl,
(timeReceived -t)*1000, addr[0])
                                elif type == 3:
                                        bytes = struct.calcsize("d")
                                        timeSent = struct.unpack("d", recvPacket[28:28 +
bytes])[0]
                                        print " %d rtt=%.0f ms %s" %(ttl,
(timeReceived-t)*1000, addr[0])
                                elif type == 0:
                                        bytes = struct.calcsize("d")
                                        timeSent = struct.unpack("d", recvPacket[28:28 +
bytes])[0]
                                        print " %d rtt=%.0f ms %s" %(ttl,
(timeReceived - timeSent)*1000, addr[0])
                                        return
                                else:
                                        print "error"
                                        break
                        finally:
                                mySocket.close()
get_route("google.com")
