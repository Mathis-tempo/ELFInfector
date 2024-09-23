section .data
	filename db "/bin/sh", 0
	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  
	is_ELF_msg db "The file is an ELF file.", 0xA, 0   ;0xA is for line break
	not_ELF_msg db "The file is not an ELF file.", 0xA, 0
	is_Directory_msg db "The file is a Directory", 0xA, 0   ;0xA is for line break
	not_Directory_msg db "The file is not a Directory", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	
section .bss 
	stat_buff resb 144 ;save space (144bytes) for the fstat command later
	
section .text
    global _start

_start:
	mov rax, 2                  ; sys_open
	mov rdi, filename      
	mov rsi, 0                ; read-only
	syscall
	test rax, rax
	js error                     ; Jump if SF=1 


	mov rbx, rax                 ; File descriptor is contained in rax after the syscall, we save it in rbx
	
	mov rsi, stat_buff
	mov rax, 0x5   ; sys_fstat
	mov rdi, rbx
	syscall        
	test rax, rax
	js error                     
	
	
	mov rax, [stat_buff + 16]  ;load st_mode (16 bytes in the stat structure) 
	and rax, 0xF000           ; mask to isolate the mask type bites (the "file type" bytes are located in the first 4 bytes) 
	cmp rax, 0x4000           ; 0x4000 = S_IFDIR
	je is_Directory
	jmp not_Directory
	
	
is_Directory:
	;Print that the file is a Directory
	mov rax, 0x1
	mov rdi, 1
	mov rsi, is_Directory_msg
	mov rdx, 24
	syscall
	jmp _end
	
	
	
not_Directory:	

	;Print that the file is not a Directory
	mov rax, 0x1
	mov rdi, 1
	mov rsi, not_Directory_msg
	mov rdx, 28
	syscall



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
	

	   
print_loop: 
	;verify file magic bytes
	mov al, [buf + rdi]
	cmp al, [ELF_numbers + rdi]
	jne not_ELF
	inc rdi
	loop print_loop
		
		
	;Print that the file is an ELF
	mov rax, 0x1
	mov rdi, 1 ;file descriptor
	mov rsi, is_ELF_msg
	mov rdx, 25    ;msg length
	syscall   
	jmp _end


not_ELF:
	;Print that the file is not an ELF
	mov rax, 0x1
	mov rdi, 1 ;file descriptor
	mov rsi, not_ELF_msg
	mov rdx, 29
	syscall



_end:			
	mov rdi, [stat_buff +0]     
	mov rax, 3      ;sys_close 
	syscall        


	mov rax, 60                  
	xor rdi, rdi                
	syscall


error:
	; Handle errors (Print & exit) 
	mov rax, 0x1
	mov rdi, 1 
	mov rsi, error_msg
	mov rdx, 30
	syscall
	mov rax, 60                 
	mov rdi, 1                    ; Exit code 1
	syscall
