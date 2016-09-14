from asm import *
from struct import pack, unpack
from collections import OrderedDict

class ElfFile64:
    base_addr = 0x80000000
    data = b''
    phdrs = OrderedDict()

    ehdr64_data = OrderedDict((
            ["TYPE"     , ["<h", 0x2]],
            ["MACHINE"  , ["<h", 0x3e]], 
            ["VERSION"  , ["<i", 0x1]],
            ["ENTRY"    , ["<q", 0x0]],
            ["PHOFF"    , ["<q", 0x40]],
            ["SHOFF"    , ["<q", 0x0]],
            ["FLAGS"    , ["<i", 0x0]],
            ["EHSIZE"   , ["<h", 0x40]],
            ["PHENTSIZE", ["<h", 0x38]],
            ["PHNUM"    , ["<h", 1]],
            ["SHENTSIZE", ["<h", 0]],
            ["SHNUM"    , ["<h", 0]],
            ["SHSTRNDX" , ["<h", 0]]
        ))

    def write_data(self):

        self.data = b'\x7fELF' + b'\x02\x01\x01\x00' + pack("<q", 0)
        for v in self.ehdr64_data.items():
            self.data += pack(v[1][0], v[1][1])

        for v in self.phdrs.items():
            for n in v[1].items():
                #print(n)
                self.data += pack(n[1][0], n[1][1])

        #exit(0)


    def add_phdr(self, name):
        self.phdrs[name] = OrderedDict((
            ["TYPE"     , ["<i", 1]],
            ["FLAGS"    , ["<i", 7]],
            ["OFFSET"   , ["<q", 0]],
            ["VADDR"    , ["<q", 0]],
            ["PADDR"    , ["<q", 0]],
            ["FILESZ"   , ["<q", 0]],
            ["MEMSZ"    , ["<q", 0]],
            ["ALIGN"    , ["<q", 0]]
        ))

    def get_phdrs(self):
        return self.phdrs
    
    def set_phdr_value(self, phdr_name, phdr_field, phdr_value):
        self.phdrs[phdr_name][phdr_field][1] = phdr_value
    
    def set_ehdr_value(self, ehdr_field, ehdr_value):
        self.ehdr64_data[ehdr_field][1] = ehdr_value

    def __init__(self):
        self.add_phdr('.text')
        self.add_phdr('.data')

        self.set_ehdr_value('PHNUM', len(self.phdrs))

        self.set_phdr_value('.text', 'VADDR', self.base_addr)
        self.set_phdr_value('.text', 'FILESZ', 0x40 + 0x38 * len(self.phdrs) + 0x200 )
        self.set_phdr_value('.text', 'MEMSZ', 0x40 + 0x38 * len(self.phdrs) + 0x200 )
       
        self.set_phdr_value('.data', 'FLAGS', 6)
        self.set_phdr_value('.data', 'VADDR', 0x90000000)
        self.set_phdr_value('.data', 'MEMSZ', 0x100)

    def get_data(self):
        return self.data

class CodeGenerator:
    def __init__(self, runtime_lib_size):
        self.asm = Asm()
        self.asm.current_position = runtime_lib_size
        self.vars = {}
        self.asm.mov_r32_imm32(esi, 0x90000000, "<I")
        self.asm.xor_r32_r32(edi, edi)

    def compile_line(self, rpn_exp):
        print("COMPILING: ", [x.value for x in rpn_exp])

        assigned_var = rpn_exp[0]

        for token in rpn_exp[2:]:
            if token.type in ['ADD']:
                #self.asm.nop(1)
                self.asm.pop_reg64(eax)
                self.asm.add_esp_mem_eax()
                #self.asm.nop(1)
            
            if token.type == 'NUM':
                self.asm.push_imm32(int(token.value))

            if token.type == 'VAR':
                self.var_load(token.value)

        self.var_assign(rpn_exp[0].value)

    def var_assign(self, var_name):
        if var_name not in self.vars:
            self.vars[var_name] = len(self.vars)

        self.asm.mov_ebx_mem_rsp()
        self.asm.mov_dil_imm8(self.vars[var_name])        
        self.asm.mov_rsi_rdi_4_ebx()
       
    def var_load(self, var_name):
        print(self.vars, var_name)
        if var_name not in self.vars:
            print("Oops!")
            exit(0)

        self.asm.mov_dil_imm8(self.vars[var_name])
        self.asm.push_rsi_rdi_4()

    def get_code(self):
        self.asm.pop_reg64(eax)
        self.asm.call_rel32(4)
        self.asm.jmp_rel32(0)
        return self.asm.get_code()


