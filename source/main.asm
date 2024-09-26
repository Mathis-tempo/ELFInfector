section .data
	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  
	is_ELF_msg db "The file is an ELF file.", 0xA, 0   ;0xA is for line break
	not_ELF_msg db "error, the file printed is not an ELF file.", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	error_msg_args db "error, only one argument is needed. Syntax : ./main file", 0xA, 0
	error_msg_file db "error, the file printed is a folder. Please enter an ELF file.", 0xA, 0
	
section .bss 
	stat_buff resb 144 ;save space (144bytes) for the fstat command later
	filename resb 256
	
section .text
    global _start

_start:
	mov rdi, [rsp]          ; get argc
	cmp rdi, 2              ; argc must be equal to 2 (name of the program + first argument) 
	jne wrong_args 
	mov rsi, [rsp +16]    ; getting the first argument 
	mov rdi, filename    ; filename buffer in rdi 
	call copy_string 
	call main
	call exit_program


wrong_args:
    mov rsi, error_msg_args  
    mov rdx, 62
    call print_message
    mov rax, 60
    mov rdi, 1
    syscall


main: 
    call stat_file	
    call check_if_regular_file
    call check_elf
    call close_file
    ret



stat_file:
    mov rax, 4      ; sys_stat
    mov rdi, filename
    mov rsi, stat_buff
    syscall
    test rax, rax
    js error
    ret


	
check_if_regular_file:
    mov rax, [stat_buff + 24]  ; load st_mode (16 bytes in the stat structure)
    and rax, 0xF000            ; mask to isolate the mask type bites (the "file type" bytes are located in the first 4 bytes) 
    cmp rax, 0x8000            ; 0x8000 = S_IFREG (regular file)
    je is_regular_file
    
    mov rsi, error_msg_file
    mov rdx, 63
    call print_message
    jmp exit_program

is_regular_file:
	ret


check_elf:
	; Open the file
	mov rax, 2      ; sys_open
	mov rdi, filename
	mov rsi, 0      ; read-only
	syscall
	test rax, rax
	js error
	mov rbx, rax    ; Save file descriptor


	; read the first 4 bytes in the file 
	mov rdi, rbx
	mov rax, 0                   ; sys_read 
	mov rsi, buf                 
	mov rdx, 4                   ; 4 octets read	
	syscall
	test rax, rax
	js error
	
	mov rcx, 4                   ; for the loop 
	xor rdi, rdi     
	
	call compare_loop
	
	mov rsi, is_ELF_msg
	mov rdx, 25   
	call print_message  
	ret
	

compare_loop: 
	;verify file magic bytes
	mov al, [buf + rdi]
	cmp al, [ELF_numbers + rdi]
	jne not_ELF
	inc rdi
	dec rcx
    	jnz compare_loop
	ret

not_ELF:
	;Print that the file is not an ELF
	mov rsi, not_ELF_msg
	mov rdx, 44
	call print_message
	jmp exit_program 




close_file:		
	mov rdi, rbx    
	mov rax, 3      ;sys_close 
	syscall        
	ret



copy_string:
    mov al, [rsi]       
    mov [rdi], al      
    test al, al        ; check if the caracter is null
    je copy_done       
    inc rsi             
    inc rdi           
    jmp copy_string     

copy_done:
    ret  
    
    
    
print_message:
    mov rax, 0x1               
    mov rdi, 1                 
    syscall
    ret

exit_program:
	mov rax, 60                  
	xor rdi, rdi                
	syscall


error:
	; Handle errors (Print & exit) 
	mov rax, 0x1
	mov rdi, 1 
	mov rsi, error_msg
	mov rdx, 31
	syscall
	mov rax, 60                 
	mov rdi, 1                    ; Exit code 1
	syscall
