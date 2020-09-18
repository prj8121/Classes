# pktsniffer.py
# Parker Johnson

import sys
import os
import struct

def fileToByteArray(fileName):
    array = []
    with open('project1.pcap', "rb") as myFile:
        bytes = myFile.read(1)
        while bytes:
            array.append(bytes.hex())
            bytes = myFile.read(1)
    return array


def pktsniffer(fileName):
    arr = fileToByteArray(fileName)
    fileSize = os.path.getsize(fileName)
    pcapGlobalHeaderLength = 24 # bytes
    indx = pcapGlobalHeaderLength
    while indx < fileSize:
        p_len, incr, p_str = packetHeader(arr, indx)
        indx += incr
        p_str, b_print = packet(arr, indx, p_len, p_str)
        if b_print:
            print(p_str)
        indx += p_len
        #sys.exit()
    

def packetHeader(arr, indx):
    incr = 16
    saved_len = arr[indx + 8 : indx + 12]
    saved_len.reverse()
    saved_len_num = int(''.join(saved_len),16)
    p_str = "PCAP: Packet size = " + str(saved_len_num) + " bytes\n"
    return saved_len_num, incr, p_str
    

def packet(arr, indx, p_len, p_str):
    return etherHeader(arr, indx, p_str)


def etherHeader(arr, indx, p_str):
    p_str += "ETHER: ----- Ether Header -----\n"
    p_str += "ETHER:\n"
    p_str += "ETHER: Destination = " + ':'.join(arr[indx:indx+6]) + ",\n"
    p_str += "ETHER: Source = " + ':'.join(arr[indx+6:indx+12]) + ",\n"
    etherType = ''.join(arr[indx+12:indx+14])
    p_str += "ETHER: Ethertype = " + etherType + "\n"
    p_str += "ETHER:\n"
    b_print = True
    if etherType == "0800":
        return ipHeader(arr, indx+14, p_str, b_print)
    else:
        return p_str, b_print
    #sys.exit()
    

def ipHeader(arr, indx, p_str, b_print):
    p_str += "IP: ----- IP Header -----\n"
    p_str += "IP:\n"
    
    version = int(arr[indx][0], 16)
    p_str += "IP: Version = " + str(version) + "\n"
    if not version == 4:
        print("I was told we were only getting IPv4")
        sys.exit()
        
    IHL = int(''.join(arr[indx][1]), 16)
    p_str += "IP: Header Length = " + str(IHL * 4) + " bytes\n"

    #DSCP
    dscpEcn = int(arr[indx+1], 16)
    dscp = dscpEcn >> 2
    p_str += "IP: Type of service = " + hex(dscp) + "\n"
        
    len_bytes = arr[indx+2: indx+4]
    #len_bytes.reverse()
    length = int(''.join(len_bytes), 16)
    p_str += "IP: Total Length = " + str(length) + " bytes\n"

    identification = int(''.join(arr[indx+4:indx+6]), 16)
    p_str += "IP: Identification = " + str(identification) + "\n"

    # Flags
    flags = int(arr[indx+6][0], 16)
    p_str += "IP: Flags = " + hex(flags) + "\n"
    flags = flags >> 1
    p_str += "IP:       = 0b" + bin(flags)[2:].rjust(3, '0') + "\n"
    
    # Frag Offset
    fragOffset = int(''.join(arr[indx+6:indx+8]),16) & int('0001111111111111')
    p_str += "IP: Fragment offset = " + str(fragOffset) + " bytes\n"

    TTL = int(''.join(arr[indx+8]), 16)
    p_str += "IP: Time to live = " + str(TTL) + " seconds/hops\n"

    protocol = int(''.join(arr[indx+9]), 16)
    p_str += "IP: Protocol = " + str(protocol) + "\n"

    headerChecksum = ''.join(arr[indx+10:indx+12])
    p_str += "IP: Header checksum = " + headerChecksum + "\n"

    src = '.'.join([str(k) for k in arr[indx+12:indx+16]])
    p_str += "IP: Source address = " + src + "\n"

    dst = '.'.join([str(k) for k in arr[indx+16:indx+20]])
    p_str += "IP: Destination address = " + dst + "\n"

    if IHL == 5:
        p_str += "IP: No options\n"
    else:
        p_str += "IP: There are options\n"

    p_str += "IP:\n"
        
    if protocol == 17:
        return udpHeader(arr, indx + (IHL*4), p_str, b_print)
    elif protocol == 1:
        return icmpHeader(arr, indx + (IHL*4), p_str, b_print)
    elif protocol == 6:
        return tcpHeader(arr, indx + (IHL*4), p_str, b_print)
    else:
        return p_str, b_print

    

def tcpHeader(arr, indx, p_str, b_print):
    p_str += "TCP: ----- TCP Header -----\n"
    p_str += "TCP:\n"

    sPortArr = arr[indx: indx+2]
    #sPortArr.reverse()
    sPort = int(''.join(sPortArr), 16)
    p_str += "TCP: Source port = " + str(sPort) + "\n"

    dPortArr = arr[indx+2: indx+4]
    #dPortArr.reverse()
    dPort = int(''.join(dPortArr), 16)
    p_str += "TCP: Destination port = " + str(dPort) + "\n"

    seqNumArr = arr[indx+4:indx+8]
    #seqNumArr.reverse()
    seqNum = int(''.join(seqNumArr), 16)
    p_str += "TCP: Sequence number = " + str(seqNum) + "\n"

    ackNumArr = arr[indx+8:indx+12]
    #ackNumArr.reverse()
    ackNum = int(''.join(ackNumArr), 16)
    p_str += "TCP: Acknowledgement number = " + str(ackNum) + "\n"

    # Data offset, Reserved, NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    dataOffset = int(arr[indx+12][0], 16)
    p_str += "TCP: Data offset = " + str(dataOffset * 4) + " bytes\n"

    flags = int(arr[indx+12][1] + arr[indx+13], 16)
    p_str += "TCP: Flags = " + hex(flags) + "\n"
    p_str += "TCP:       = 0b" + bin(flags)[2:].rjust(12,'0') + "\n"
    
    winSize = int(''.join(arr[indx+14:indx+16]), 16)
    p_str += "TCP: Window = " + str(winSize) + "\n"

    checksum = ''.join(arr[indx+16:indx+18])
    p_str += "TCP: Checksum = " + checksum + "\n"

    urg = ''.join(arr[indx+18:indx+20])
    p_str += "TCP: Urgent pointer = " + urg + "\n"

    if dataOffset == 5:
        p_str += "TCP: No options\n"
    else:
        p_str += "TCP: There are options\n"
    
    p_str += "TCP:\n"

    return p_str, b_print


def icmpHeader(arr, indx, p_str, b_print):
    p_str += "ICMP: ----- ICMP Header -----\n"
    p_str += "ICMP:\n"

    icmpType = int(arr[indx], 16)
    p_str += "ICMP: Type = " + str(icmpType) + "\n"

    code = int(arr[indx+1], 16)
    p_str += "ICMP: Code = " + str(code) + "\n"

    checksum = ''.join(arr[indx+2: indx+4])
    p_str += "ICMP: Code = " + checksum + "\n"

    # Rest of header depends on type and code
    
    p_str += "ICMP:\n"

    return p_str, b_print


def udpHeader(arr, indx, p_str, b_print):
    p_str += "UDP: ----- UDP Header -----\n"
    p_str += "UDP:\n"
    
    sPortArr = arr[indx:indx+2]
    srcPort = int(''.join(sPortArr), 16)
    p_str += "UDP: Source port = " + str(srcPort) +"\n"

    dPortArr = arr[indx+2:indx+4]
    dstPort = int(''.join(dPortArr), 16)
    p_str += "UDP: Destination port = " + str(dstPort) + "\n"

    length = int(''.join(arr[indx+4:indx+6]), 16)
    p_str += "UDP: Length = " + str(length) + "\n"

    p_str += "UDP: Checksum = " + ''.join(arr[indx+6:indx+8]) + "\n"
    
    p_str += "UDP:\n"

    return p_str, b_print
    

def b_arr_to_num(arr):
    s = ""
    for c in arr:
        s += (c.decode('hex'))
    return s        


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "-r":
        pktsniffer(sys.argv[2])
    else:
        print("Usage: python pktsniffer -r file");


main()
