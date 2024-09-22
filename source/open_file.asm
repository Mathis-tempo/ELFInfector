section .data
    filename db "../tests/test", 0
    buf times 4 db 0            ; Buffer for the 4 first bytes

section .text
    global _start

_start:
    mov rax, 2                  ; open
    mov rdi, filename      
    mov rsi, 0                
    syscall


    ; read the 4 first octets in the file 
    mov rdi, rax                 ; File descriptor is contained in rax after the syscall
    mov rax, 0                   ; read 
    mov rsi, buf                 
    mov rdx, 4                   ; 4 octets read	
    syscall



    mov rax, 60                  
    xor rdi, rdi                
    syscall



