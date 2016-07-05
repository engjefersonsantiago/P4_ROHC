#!/usr/bin/env python
#
# Copyright 2015,2016 Didier Barvaux
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

"""
Example that shows how to compress, then decompress a sequence of packets
"""

from __future__ import print_function
from __future__ import division
from __future__ import unicode_literals
from __future__ import absolute_import

from builtins import range
from builtins import int
from builtins import bytes

from future import standard_library
standard_library.install_aliases()

import sys
import struct

from rohc import *
from RohcCompressor import *
from RohcDecompressor import *

# Packets manipulation
from scapy.all import sniff
from scapy.all import Ether, IP, IPv6
from scapy.all import sendp, hexdump

RTP_PAYLOAD = 'hello, Python world!'

def print_usage():
    print("usage: example.py packets_number eth_int [verbose [verbose]]")

verbose_level = 0
verbose_rohc = False
if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 4 and len(sys.argv) != 5:
    print_usage()
    sys.exit(1)
packets_nr = int(sys.argv[1])
eth_int = str(sys.argv[2])
if len(sys.argv) >= 4:
    if sys.argv[3] != 'verbose':
        print_usage()
        sys.exit(1)
    if len(sys.argv) < 5:
        verbose_level = 1
    else:
        if sys.argv[4] != 'verbose':
            print_usage()
            sys.exit(1)
        verbose_level = 2
        verbose_rohc = True

# create a stream of IPv4/UDP/RTP packets
print("create a stream of RTP packets")
uncomp_pkts = []

# IP header section
ip_hdr_fmt = '!BBHHHBB2s4s4s'
ip_hdr_len = struct.calcsize(ip_hdr_fmt) # bytes

# UDP header section
udp_hdr_fmt = '!HHH2s'
udp_hdr_len = struct.calcsize(udp_hdr_fmt) # bytes

# RTP header section
rtp_hdr_fmt = '!BBHII'
rtp_hdr_len = struct.calcsize(rtp_hdr_fmt) # bytes
udp_pkt_len = udp_hdr_len + rtp_hdr_len + len(RTP_PAYLOAD)

# IP header fields
ip_header = IP()

ip_src = "127.0.0.1"
ip_src = "192.168.119.128"
ip_dst = "255.255.255.255"
ip_dst = "2.2.2.255"

index = 0
ip_dest = [0,0,0,0]
ip_dest[index] =  ""

for i in ip_dst:
    if i.isdigit():
        ip_dest[index] = str(ip_dest[index]) + str(i)
    else:
        index += 1
        ip_dest[index] =  ""

index = 0
ip_source = [0,0,0,0]
ip_source[index] =  ""

for i in ip_src:
    if i.isdigit():
        ip_source[index] = str(ip_source[index]) + str(i)
    else:
        index += 1
        ip_source[index] =  ""

print(ip_source)
print(ip_dest)

ip_header.version= 4
ip_header.ihl = ip_hdr_len // 4
ip_header.tos = 0x0
ip_header.len = (ip_hdr_len + udp_pkt_len)
ip_header.id = 0
ip_header.flags =0 
ip_header.frag = 0
ip_header.ttl = 64
ip_header.proto= 17
#ip_header.chksum= 0x7ce6
ip_header.src = ip_src
ip_header.dst = ip_dst
del ip_header.chksum 
ip_header = ip_header.__class__(str(ip_header)) 

#ip_header.show2()
#print("-------------------------------------")
#hexdump((ip_header.version << 4) | ip_header.ihl)
#print(ip_header.version << 4)
#print(ip_header.ihl)
#print(ip_header.proto)
#hexdump(ip_header)

#ip_pkt_len = ip_hdr_len + udp_pkt_len
#ip_version = 4
#ip_ihl = ip_hdr_len // 4
#ip_tos = 0
#ip_id = 0
#ip_frag_off = 0
#ip_ttl = 64
#ip_proto = 17 # UDP
#ip_chksum = b'\x7c\xaf' # hardcoded IP checksum to avoid computation
ip_chksum = struct.pack('!BB', ip_header.chksum >> 8, ip_header.chksum & 0xFF)
ip_saddr = struct.pack('!BBBB', int(ip_source[0]), int(ip_source[1]), int(ip_source[2]), int(ip_source[3]))
ip_daddr = struct.pack('!BBBB', int(ip_dest[0]), int(ip_dest[1]), int(ip_dest[2]), int(ip_dest[3]))

# UDP header fields
udp_sport = 1235
udp_dport = 1234
udp_chksum = b'\x00\x00' # disable UDP checksum for better compression

# RTP header fields
rtp_version = 2
rtp_padding_bit = 0
rtp_ext_bit = 0
rtp_cc = 0
rtp_marker = 0
rtp_pt = 0
rtp_ssrc = 0

for i in range(0, packets_nr):
    rtp_seq = i
    rtp_ts = i * 300
    ip_packet = pack(ip_hdr_fmt + udp_hdr_fmt[1:] + rtp_hdr_fmt[1:],\
                     (ip_header.version << 4) | ip_header.ihl, ip_header.tos, ip_header.len, ip_header.id, \
                     ip_header.frag, ip_header.ttl, ip_header.proto, ip_chksum, ip_saddr, ip_daddr, \
                     udp_sport, udp_dport, udp_pkt_len, udp_chksum, \
                     (rtp_version << 6) | (rtp_padding_bit << 5) | (rtp_ext_bit << 4) | rtp_cc, \
                     (rtp_marker << 7) | rtp_pt, rtp_seq, rtp_ts, rtp_ssrc)
    #hexdump(ip_packet)
    ip_packet += bytes(RTP_PAYLOAD, encoding='utf-8')
    #hexdump(ip_packet)
    uncomp_pkts.append(ip_packet)

print("%i %i-byte RTP packets created with %i-byte payload" \
      % (len(uncomp_pkts), len(uncomp_pkts[0]), len(RTP_PAYLOAD)))

# create one ROHC compressor
print("create ROHC compressor")
comp = RohcCompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if comp is None:
    print("failed to create the ROHC compressor")
    sys.exit(1)

# create one ROHC decompressor
print("create ROHC decompressor")
decomp = RohcDecompressor(cid_type=ROHC_LARGE_CID, profiles=[ROHC_PROFILE_RTP], \
        verbose=verbose_rohc)
if decomp is None:
    print("failed to create the ROHC decompressor")
    sys.exit(1)

# compress/decompress the packets, one by one
pkts_nr = 0
uncomp_len = 0
comp_len = 0
for uncomp_pkt in uncomp_pkts:
    pkts_nr += 1
    uncomp_len += len(uncomp_pkt)

    if verbose_level == 0:
        # once python2 support is not needed anymore
        #print('.', flush=True, end='')
        print('.', end='')
        sys.stdout.flush()

    # compression
    if verbose_level >= 1:
        print("compress   packet #%i: %i bytes -> " % (pkts_nr, len(uncomp_pkt)), end='')
    (status, comp_pkt) = comp.compress(uncomp_pkt)
    if status != ROHC_STATUS_OK:
        print("failed to compress packet: %s (%i)" % (rohc_strerror(status), status))
        sys.exit(1)
    if verbose_level >= 1:
        print(len(comp_pkt), "bytes")
    comp_len += len(comp_pkt)

    # Send a packet over the Ethernet
    eth_pkt = Ether(src="00:0c:29:5b:46:b3",type=0x0800)/comp_pkt
    #eth_pkt = Ether(src="00:0c:29:5b:46:b3",type=0x0800)/str(uncomp_pkt)
    hexdump(eth_pkt)
   
    import socket
    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x03))
    send_socket.bind((eth_int, 0))
    send_socket.send(str(eth_pkt))

    #sendp(eth_pkt, iface=eth_int, verbose=0)

    # decompression
    ######if verbose_level >= 1:
    ######    print("decompress packet #%i: %i bytes -> " \
    ######          % (pkts_nr, len(comp_pkt)), end='')
    ######(status, decomp_pkt, _, _) = decomp.decompress(comp_pkt)
    ######if status != ROHC_STATUS_OK:
    ######    print("failed to decompress packet: %s (%i)" \
    ######          % (rohc_strerror(status), status))
    ######    sys.exit(1)
    ######if verbose_level >= 1:
    ######    print(len(decomp_pkt), "bytes")

    ####### compare the decompressed packet with the original one
    ######if decomp_pkt != uncomp_pkt:
    ######    print("decompressed packet does not match original packet")
    ######    sys.exit(1)

#####if verbose_level == 0:
#####    print()
#####print("all %i packets were successfully compressed" % pkts_nr)
####
#####gain = uncomp_len - comp_len
#####gain_percent = 100 - comp_len * 100 / uncomp_len
#####if gain == 0:
#####    print("no byte saved by compression")
#####elif gain > 0:
#####    print("%i bytes (%i%%) saved by compression" % (gain, gain_percent))
#####else:
#####    print("%i bytes (%i%%) lost by compression" % (abs(gain), abs(gain_percent)))

