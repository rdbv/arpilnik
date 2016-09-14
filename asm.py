from struct import *

NO_DISPLACEMENT_MOD = 0b00
DISPLACEMENT_BYTE_MOD = 0b01
DISPLACEMENT_WORD_MOD = 0b10
REGISTER_MOD = 0b11

REG_RM_AX = 0b000
REG_RM_CX = 0b001
REG_RM_DX = 0b010
REG_RM_BX = 0b011

class GPR:
    def __init__(self, val):
        self.val = val

eax = GPR(REG_RM_AX)
ebx = GPR(REG_RM_BX)
ecx = GPR(REG_RM_CX)
edx = GPR(REG_RM_DX)
esp = GPR(0)
ebp = GPR(0)
esi = GPR(0)
edi = GPR(0b111)

class Asm:
    
    def __init__(self):
        self.code = b''
        self.current_position = 0
   
    def mov_r32_imm32(self, reg, imm, unsigned = "<i"):
        mov_map = {eax : b'\xb8', ecx : b'\xb9', edx : b'\xba', ebx : b'\xbb', \
                   esp : b'\xbc', ebp : b'\xbd', esi : b'\xbe', edi : b'\xbf'}
        self.emit(mov_map[reg] + pack(unsigned, imm))
    
    def mov_dil_imm8(self, imm8):
        self.emit(b'\x40\xb7' + pack("<b", imm8))
   
    def mov_ebx_mem_rsp(self):
        self.emit(b'\x8b\x1c\x24')

    def mov_rsi_rdi_4_ebx(self):
        self.emit(b'\x89\x1c\xbe')

    def xor_r32_r32(self, left, right):
        self.emit(b'\x31' + self.modrm(REGISTER_MOD, right.val, left.val))

    def add_esp_mem_eax(self):
        self.emit(b'\x01' + b'\x04' + b'\x24')

    def pop_reg64(self, reg):
        pop_map = {eax : b'\x58', ecx : b'\x59', edx : b'\x5a', ebx : b'\x5b'}
        self.emit(pop_map[reg])

    def push_rsi_rdi_4(self):
        self.emit(b'\xff\x34\xbe')

    def push_imm32(self, imm):
        self.emit(b'\x68' + pack("<i", imm))

    
    def jmp_rel8(self, rel8):
        self.emit(b'\xeb' + pack("<b", rel8 - self.current_position - 2))
    
    def jmp_rel32(self, rel32):
        self.emit(b'\xe9' + pack("<i", rel32 - self.current_position - 5))
    
    def call_rel32(self, rel32):
        self.emit(b'\xe8' + pack("<i", rel32 - self.current_position - 5))

    def nop(self, repeat = 1):
        self.emit(b'\x90' * repeat)


    def int(self, int_no):
        self.emit(b'\xcd' + pack("<B", int_no))


    def modrm(self, mod, reg, rm):
        return pack("<B", mod << 6 | reg << 3 | rm)

    def inc_position(self, code):
        self.current_position += len(code)
        return code
    
    def emit(self, data):
        self.code += self.inc_position(data)
    
    def get_code(self):
        return self.code
    
    def get_pos(self):
        return self.current_position

