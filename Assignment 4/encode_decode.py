#!/usr/bin/python

# Encoder / Decoder from Assignment 6
# StudentID - SLAE-3763
# Author : Alain Menelet


import random
import argparse

def main():
    parser = argparse.ArgumentParser(prog='Encoder Python SLAE', description="Encoder shellcode")
    parser.add_argument('-s', dest="shellcode",type=str, help="shellcode", required=True)
    parser.add_argument('-a', dest="action", default="encode", help="encode or decode")
    args = parser.parse_args()


    if args.action == "encode":
        encode(args.shellcode)
    elif args.action == "decode":
        decode(args.shellcode)
    else:
        print "erreur dans la saisie de l'action"


def clear(shellcode):
    return shellcode.replace('\\x','')



def encode(shellcode):
    """
    Encode the shellcode
    :param shellcode: string
    :return:
    """
    encoded = ""
    shell = bytearray.fromhex(clear(shellcode))
    for i in range(0,len(shell) - 1, 2):
        temp = random.randint(1, 10)
        while (((shell[i] ^ shell[i+1]) + temp >= 0xff) or (shell[i] ^ shell[i+1]) + temp == 0):
            temp = random.randint(1, 10)

        encoded += '\\x%02x' % temp
        encoded += '\\x%02x' %((shell[i] ^ shell[i+1]) + temp)
        encoded += '\\x%02x' % (shell[i+1] + temp)

    if (len(bytearray(shell)) % 2):
        while (shell[-1] == temp and (shell[-1] ^ temp == 0)):
            temp = random.randint(1, 10)
        encoded += '\\xFF'
        encoded += '\\x%02x' % temp
        encoded += '\\x%02x' % (shell[-1] ^ temp)

    print 'Taille %d' % len(bytearray(shell))
    print encoded


def decode(shellcodeEncoded):
    """
    Decode the shellcode
    :param shellcodeEncoded: string
    :return:
    """
    shellD = bytearray.fromhex(clear(shellcodeEncoded))
    decoded = ""

    for i in range(0, len(bytearray(shellD))-3,3):
        ran = shellD[i]
        decoded += '\\x%02x' % ((shellD[i + 1] - ran) ^ (shellD[i + 2]-ran))
        decoded += '\\x%02x' % (shellD[i + 2] - ran)

    if shellD[-3] == 255:
        decoded += '\\x%02x' % (shellD[-1] ^ shellD[-2])
    else:
        ran = shellD[-3]
        decoded += '\\x%02x' % ((shellD[-2] - ran) ^ (shellD[-1] - ran))
        decoded += '\\x%02x' % (shellD[-1] - ran)



    print 'Taille %d' % len(bytearray(decoded))
    print decoded



if __name__=='__main__':
    main()
