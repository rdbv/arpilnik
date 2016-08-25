from struct import *

# Basic EL64 header
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

    def get_data(self):
        return self.file_data + self.code
    

class CodeGenerator:
    def compile_exp(self, rpn_exp):
        
        pass
