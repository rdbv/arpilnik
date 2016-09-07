from struct import pack
from parser import operators

embd_functions = [
    "$t", 
]

# Basic ELF64 header
# Only for now, ELF soon will be rewritten
class Elf64_File:
    file_data = b'' 
    code = b'' 
    basic_addr = 0x80000000

    def __init__(self, code = ""):
        self.code = code
        self.ep = self.basic_addr + 0x40 + 0x38*2 # entry point
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
        self.file_data += pack("<h", 2)        # phnum
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
        # PHDR_DATA (VARMEM)
        self.file_data += pack("<i", 1)                     # type
        self.file_data += pack("<i", 6)                     # flags
        self.file_data += pack("<q", 0)                     # offset
        self.file_data += pack("<q", self.basic_addr + 0x10000000)       # vaddr
        self.file_data += pack("<q", self.basic_addr)       # paddr
        self.file_data += pack("<q", 0)   # filesz
        self.file_data += pack("<q", 0x100)   # memsz
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

    def push_addr64(self, reg):
        ops_push = {'ax' : b'\x30', 'cx' : b'\x31', 'dx' : b'\x32', 'bx' : b'\x33'}
        return b'\xff' + ops_push[reg]

    def add_reg_reg64(self, dest, src):
        return self.rex_w + b'\x01' + self.modrm(REGISTER_MOD, self.regtab[src], self.regtab[dest])
    
    def sub_reg_reg64(self, dest, src):
        return self.rex_w + b'\x29' + self.modrm(REGISTER_MOD, self.regtab[src], self.regtab[dest])
    
    def mov_reg_imm64(self, dest, imm):
        ops_mov = {'ax' : b'\xb8', 'cx' : b'\xb9', 'dx' : b'\xba', 'bx' : b'\xbb'}
        return self.rex_w + ops_mov[dest] + pack("<Q", imm)

    def mov_reg_reg64(self, dest, src):
        return self.rex_w + b'\x89' + self.modrm(REGISTER_MOD, self.regtab[src], self.regtab[dest])
    
    def mov_regmem8_reg64(self, dest, src, dis):
        out = self.rex_w + b'\x89'
        out += self.modrm(DISPLACEMENT_BYTE_MOD, self.regtab[src], self.regtab[dest])
        out += pack("<B", dis) 
        return out 

    def modrm(self, mod, reg, rm):
        return pack("<B", mod << 6 | reg << 3 | rm)

class Code_Generator_x86_64:
    def init_binary(self):
        self.asm = Assembler_x86_64()
        self.elf_file = Elf64_File()
        self.data = b''
        self.exit_seq = self.asm.pop_reg32('bx') + b'\xb8\x01\x00\x00\x00' + b'\xcd\x80'
        self.var_list = []
        self.var_begin_addr = 0x90000000 

    def compile_line(self, line):
        self.compile_exp(line)        

    def add_exit_seq(self):
        self.data += self.exit_seq

    def compile_exp(self, rpn_exp):
        i = 0
        while i < len(rpn_exp):
            token = rpn_exp[i]
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
                # Assignment of <var>=
                if is_valid_varname(token) and rpn_exp[i+1] == '=':
                    varname = token
                    var_vaddr = self.var_begin_addr + (len(self.var_list) * 8)
                    var_num = len(self.var_list)
                    var_val = int(rpn_exp[i+2])
                    self.var_list.append([varname, var_vaddr, var_val])
                    self.data += self.asm.mov_reg_imm64('ax', var_vaddr)
                    self.data += self.asm.mov_reg_imm64('bx', var_val)
                    self.data += self.asm.mov_regmem8_reg64('ax', 'bx', 0)
                    i += 3
                    continue
                elif is_valid_varname(token):
                    # Use of variable
                    var = self.get_variable_data(token)
                    self.data += self.asm.mov_reg_imm64('ax', var[1])
                    self.data += self.asm.push_addr64('ax')
                else:
                    # Digit
                    self.data += self.asm.push_imm_32(int(token))
            i += 1        

    def get_raw_code(self):
        return self.data

    def get_code(self):
        return self.elf_file.get_header() + self.data

    def get_variable_data(self, varname):
        for v in self.var_list:
            if varname == v[0]:
                return v
        raise RuntimeError("Nieee maaa!")

    def print_varlist(self):
        for v in self.var_list:
            print(v[0], hex(v[1]), v[2])


