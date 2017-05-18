bits 32

global _start;

putc:
    push ebx
    push ecx
    push edx
    mov ebx, CHAR_BUF
    mov [ebx], al
    mov eax, 4
    mov ebx, 1
    mov ecx, CHAR_BUF
    mov edx, 1
    int 0x80
    pop edx
    pop ecx
    pop ebx
    ret
    BUF_CHAR: db 0x90

print_num_signed:
    test eax, eax
    jz zero    
    jns _ns
        push eax
        mov al, '-'
        call putc
        pop eax
        neg eax
    _ns:
    xor ecx, ecx
    mov ebx, 10
    _n0:
        test eax, eax
        jz _n1
        xor edx, edx
        div ebx
        add edx, '0'
        mov esi, NUM_BUF
        mov byte [esi+ecx], dl
        inc ecx
        jmp _n0
    _n1:
        dec ecx
        add esi, ecx
        inc ecx
        _n2:
            mov al, byte [esi]         
            call putc
            dec esi
            dec ecx
            jnz _n2 
            ret
    zero:
        mov al, '0'
        call putc
        ret

print_num_nl:
    call print_num_signed
    mov eax, 0xa
    call putc
    ret

exit:
    mov eax, 1
    xor ebx, ebx
    int 0x80

section .data
    NUM_BUF: times 16 db 0
    CHAR_BUF: db 0
