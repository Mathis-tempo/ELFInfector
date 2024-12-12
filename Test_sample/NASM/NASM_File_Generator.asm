; This allows us to create a PT_NOTE segment :
; The .note.ABI-tag section is recognized by the linker to create a PT_NOTE segment
section .note.ABI-tag note alloc
    align 4                 ; Align on 4-byte boundary as required by ELF note format
    dd 4                    ; Size of name field 
    dd 16                   ; Size of descriptor
    dd 1                    ; Type of note (NT_GNU_ABI_TAG = 1)
    db "GNU", 0            ; Name of the note (GNU\0)
    dd 0                   ; Operating system (Linux = 0)
    dd 3,2,0              ; ABI version (major.minor.patch)

section .text
global _start         

_start:
    ; Write "Hello"
    mov rax, 1           
    mov rdi, 1           
    mov rsi, msg      
    mov rdx, msg_len     
    syscall

    ; Exit program
    mov rax, 60          
    xor rdi, rdi         
    syscall

section .data
msg: db "Hello", 0xa     
msg_len: equ $ - msg    

; Note: Sometime to create a PT_NOTE segment using .note.ABI-tag,
; the linker (ld) not always convert this into a PT_NOTE program header.
; If this happens, consider using gcc for linking or modifying the binary after compilation to add the PT_NOTE