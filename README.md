PL/0 Language compiler to x86 assembly, without _any_ optimalizations.
So code is propably not fast and good-looking, but this is my first compiler written for fun. :)

PL/0 is designed for learning, and semicolons are bit tricky, sorry for that,
look into examples to check basic programs, and look on semicolons - after last instruction in block
DON'T write semicolon.

runtime.asm is for 'print', 'exit' functions.

#### Usage
```
-s <input file>
-o <output file>
-asm don't assembly file, just emit assembler
     for assembling required NASM!

./arpilnik.py -s examples/simplest.pl0 -o main.asm -asm
Compiled with no errors, i think...

(If -asm, then assembly by hand)
nasm -f elf32 main.asm -o main.o
ld -m elf_i386 main.o -o main
```

For example, simplest.pl0 compile to

```
_start:
    mov eax, 666;  
    mov dword [global_var_var0], eax;  
    mov eax, dword [global_var_var0] ; VAR_ARG var0;  
    call print_num_nl;  
    call exit;  

section .data
    global_var_var0 dd 0;  
```

And loop_and_if.pl0, to
```
proc_loopy:
    push ebp;  
    mov ebp, esp;  
    sub esp, 4;  
    ; WHILE ;  
W1:
    mov eax, dword [ebp-4];  
    mov [spill_var_0], eax;  
    mov eax, 100;  
    cmp [spill_var_0], eax;  
    jge E1;  
B1:
    mov eax, dword [ebp-4];  
    add eax, 1;  
    mov dword [ebp-4], eax;  
    mov ebx, dword [global_var_var0];  
    add ebx, 2;  
    mov dword [global_var_var0], ebx;  
    mov eax, dword [ebp-4] ; VAR_ARG i;  
    call print_num_nl;  
    jmp W1;  
E1:
    ; INEND ;  
    add esp, 4;  
    pop ebp;  
    ret;  


_start:
    call proc_loopy;  
    ; IF ;  
    mov eax, dword [global_var_var0];  
    mov [spill_var_0], eax;  
    mov eax, 10;  
    cmp [spill_var_0], eax;  
    jle L1;  
    ; ELSE ;  
    mov eax, dword [global_var_var0] ; VAR_ARG var0;  
    call print_num_nl;  
L1:
    call exit;  

section .data
    spill_var_0 dd 0;  
    global_var_var0 dd 0;  
```

