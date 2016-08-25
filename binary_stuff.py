from struct import *
from parser import operators

# Basic EL64 header
# Only for now, ELF soon will be rewritten
class Elf64_File:
    file_data = b'' 
    code = b'' 
    basic_addr = 0x80000000

    def __init__(self, code = ""):
        self.code = code
        self.ep = self.basic_addr + 0x40 + 0x38 # entry point
        # E_IDENT
        self.file_data += b'\x7fELF'  
        self.file_data += b"\x02\x01\x01\x00"
        self.file_data += pack("<q", 0)
        # EHDR
        self.file_data += pack("<h", 2)        # type
        self.file_data += pack("<h", 0x3e)     # machine
        self.file_data += pack("<i", 0x1)      # version
        self.file_data += pack("<q", self.ep)  # entry
        self.file_data += pack("<q", 0x40)     # phoff
        self.file_data += pack("<q", 0)        # shoff
        self.file_data += pack("<i", 0)        # flags
        self.file_data += pack("<h", 0x40)     # ehsize
        self.file_data += pack("<h", 0x38)     # phentsize
        self.file_data += pack("<h", 1)        # phnum
        self.file_data += pack("<h", 0)        # shentsize
        self.file_data += pack("<h", 0)        # shnum
        self.file_data += pack("<h", 0)        # shstrndx
        # PHDR
        self.file_data += pack("<i", 1)                     # type
        self.file_data += pack("<i", 7)                     # flags
        self.file_data += pack("<q", 0)                     # offset
        self.file_data += pack("<q", self.basic_addr)       # vaddr
        self.file_data += pack("<q", self.basic_addr)       # paddr
        self.file_data += pack("<q", 0x40+0x38+len(code))   # filesz
        self.file_data += pack("<q", 0x40+0x38+len(code))   # memsz
        self.file_data += pack("<q", 0)                     # align

    def get_header(self):
        return self.file_data

    def get_data(self):
        return self.file_data + self.code


NO_DISPLACEMENT_MOD = 0b00
DISPLACEMENT_BYTE_MOD = 0b01
DISPLACEMENT_WORD_MOD = 0b10
REGISTER_MOD = 0b11

REG_RM_AX = 0b000
REG_RM_CX = 0b001
REG_RM_DX = 0b010
REG_RM_BX = 0b011

''' Simple class for assembling, ofc support only needed instructions '''
class Assembler_x86_64:
    # rex prefixes
    rex_w = b'\x48'
    regtab = {
            'ax' : REG_RM_AX,
            'cx' : REG_RM_CX,
            'dx' : REG_RM_DX,
            'bx' : REG_RM_BX
    }

    def push_reg32(self, reg_str):
        ops_push = {'ax' : b'\x50', 'cx' : b'\x51', 'dx' : b'\x52', 'bx' : b'\x53' }
        return ops_push[reg_str]

    def pop_reg32(self, reg_str):
        ops_pop = {'ax' : b'\x58', 'cx' : b'\x59', 'dx' : b'\x5a', 'bx' : b'\x5b' }
        return ops_pop[reg_str]

    def push_imm_32(self, val):
        return b'\x68' + pack("<i", val)

    def add_reg_reg64(self, dest, src):
        return self.rex_w + b'\x01' + self.modrm(REGISTER_MOD, self.regtab[src], self.regtab[dest])
    
    def sub_reg_reg64(self, dest, src):
        return self.rex_w + b'\x29' + self.modrm(REGISTER_MOD, self.regtab[src], self.regtab[dest])

    def modrm(self, mod, reg, rm):
        return pack("<B", mod << 6 | reg << 3 | rm)

class Code_Generator_x86_64:
    def init_binary(self):
        self.asm = Assembler_x86_64()
        self.elf_file = Elf64_File()
        self.data = self.elf_file.get_header()
        self.exit_seq = b'\xb8\x01\x00\x00\x00' + self.asm.pop_reg32('bx') + b'\xcd\x80'

    def compile_exp(self, rpn_exp):
        for token in rpn_exp:
            if token in operators:
                self.data += self.asm.pop_reg32('ax')
                self.data += self.asm.pop_reg32('bx')
                if token == '-':
                    self.data += self.asm.sub_reg_reg64('bx', 'ax')
                    self.data += self.asm.push_reg32('bx')
                if token == '+':
                    self.data += self.asm.add_reg_reg64('bx', 'ax')
                    self.data += self.asm.push_reg32('bx')
            else:
                # Digit
                self.data += self.asm.push_imm_32(int(token))
        
        self.data += self.exit_seq

    def get_code(self):
        return self.data


