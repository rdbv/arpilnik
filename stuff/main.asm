; ELF Header
bits 64

org 0x80000000

ehdr:

db 0x7f, "ELF"  ; E_IDENT
db 0x2          ; EI_CLASS
db 0x1          ; EI_DATA
db 0x1          ; EI_VERSION
db 0x0          ; EI_PAD
times 8 db 0    ; EI_NINDENT

dw 2           ; E_TYPE
dw 0x3e        ; E_MACHINE
dd 1           ; E_VERSION
dq main        ; E_ENTRY
dq ehsize      ; E_PHOFF
dq 0           ; E_SHOFF
dd 0           ; E_FLAGS
dw ehsize      ; E_EHSIZE
dw phsize      ; E_PHENTSIZE
dw 2           ; E_PHNUM
dw 0           ; E_SHENTSIZE
dw 0           ; E_SHNUM
dw 0           ; E_SHSTRNDX

ehsize equ $ - ehdr

phdr_text:
dd  1          ; P_TYPE
dd  7          ; P_FLAGS
dq  0          ; P_OFFSET
dq  $$         ; P_VADDR
dq  0          ; P_PADDR
dq  filesz     ; P_FILESZ
dq  filesz     ; P_MEMSZ
dq  0          ; P_ALIGN

phsize equ $ - phdr_text

phdr_data:
dd  1          ; P_TYPE
dd  6          ; P_FLAGS
dq  0          ; P_OFFSET
dq  $$+0x10000000  ; P_VADDR
dq  0          ; P_PADDR
dq  0          ; P_FILESZ
dq  0x100      ; P_MEMSZ
dq  0          ; P_ALIGN

mem_addr equ 0x90000000

main:

    mov rcx, mem_addr
    mov qword [rcx], 0x233233

    push qword [rax]
    push qword [rcx]
    push qword [rdx]

    nop
    nop
 
    mov rax, 1
    int 0x80


filesz equ $ - $$
