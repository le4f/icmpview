#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pcap
import sys,string,time,socket,struct

def rtn_local_ip(ifname): 
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    inet = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15])) 
    ret = socket.inet_ntoa(inet[20:24]) 
    return ret

def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

def print_packet(pktlen, data, timestamp):
    if not data:
        return
    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        if decoded['destination_address'] == localip and decoded['source_address'] != localip:
            print '[*]%s Ping From: %s' % (current_date, decoded['source_address'])

if __name__=='__main__':
    if len(sys.argv) < 2:
        print 'usage: icmpview.py <interface>'
        sys.exit(0)
    p = pcap.pcapObject()
    dev = sys.argv[1]
    global localip
    localip = rtn_local_ip(dev)
    print '[!]Listen Addr %s' % localip
    net, mask = pcap.lookupnet(dev)
    p.open_live(dev, 1600, 0, 100)
    p.setfilter('icmp', 0, 0)
    try:
        while 1:
            p.dispatch(1, print_packet)
    except KeyboardInterrupt:
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

