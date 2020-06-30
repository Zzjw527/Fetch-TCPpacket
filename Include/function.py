import os
from scapy.all import sniff,wrpcap,Raw,IP,TCP
import re
import dpkt
import time
from winpcapy import WinPcapUtils

imf=[]

def packet_callbacke(packet):
    getimf=packet.summary()
    ag =re.search(r'TCP (.*):.* > (.*?):.*', str(getimf), re.M | re.I)
    if ag:
        imf.append("***源ip地址： "+ag.group(1))
        imf.append("***目的ip地址： "+ag.group(2))
    else:
        print("GG")

def start_count():
    imf.clear()
    pcap = sniff(filter="tcp and tcp port 80",prn=packet_callbacke,count =1)
    imf.append("***源MAC地址： " + pcap[TCP][0].src)
    imf.append("***目的MAC地址： " + pcap[TCP][0].dst)
    imf.append("***数据包长度： " + str(pcap[TCP][0].len))
    imf.append("***发送端口号： " + str(pcap[TCP][0].sport))
    imf.append("***接收端口号： " + str(pcap[TCP][0].dport))
    imf.append("***传输层协议类型： " + str(pcap[TCP][0].proto)+"(TCP)")
    return imf

def isNetOK(testserver):
    s=socket.socket()
    s.settimeout(3)
    try:
        status = s.connect_ex(testserver)
        if status == 0:
            s.close()
            return True
        else:
            return False
    except Exception as e:
        return False

def isNetChainOK(testserver=('www.baidu.com',443)):
    isOK = isNetOK(testserver)
    return isOK

def chawinpcap():
    def packet_callback(win_pcap, param, header, pkt_data):
        # Assuming IP (for real parsing use modules like dpkt)
        ip_frame = pkt_data[14:]
        # Parse ips
        src_ip = ".".join([str(b) for b in ip_frame[0xc:0x10]])
        dst_ip = ".".join([str(b) for b in ip_frame[0x10:0x14]])
        print("%s -> %s" % (src_ip, dst_ip))
    WinPcapUtils.capture_on("*Ethernet*", packet_callback)