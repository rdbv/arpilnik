import sys; 
sys.dont_write_bytecode = True

from asm  import *
from parser import *
from arpilnik import *

def get_file(name):
    try:
        f = open(name, "r")
    except:
        print("Cannot open file: %s" % name)
        exit(0)
    content = f.read().split('\n')
    content = [x for x in content if x]
    return content


OBJDUMP_CMD = b'''clear;objdump -b binary -m i386:x64-32 \
                  -M intel --start-address=%d --stop-address=0x200 -D main'''
READELF_CMD = b'''readelf -a main'''

def write_fifo():
    R2_CMD = b"clear;r2 -d main -c 'pd 17 @ entry0' -q"
    fifo = open("stuff/in0.fifo", "wb")
    rts = len(open('stuff/rt.bin', 'rb').read())
    #rts = 0
    k = OBJDUMP_CMD % (0xb0 + rts)

    fifo.write(k)
    #fifo.write(READELF_CMD)
    fifo.close()

def main():
    f = get_file('stuff/prog')
    runtime = open('stuff/rt.bin', 'rb').read()

    elf = ElfFile64()
    parser = Parser()
    cg = CodeGenerator(len(runtime))
    
    line_number = 0

    for line in f:
        cg.compile_line(infix_to_rpn(parser.parse(line, line_number)))
        line_number += 1

    elf.set_ehdr_value('ENTRY', elf.base_addr + 0x40 + 0x38 * 2 + len(runtime))
    elf.write_data()
    
    out_file = open('stuff/main', 'wb')
    out_file.write(elf.get_data() + runtime + cg.get_code())
    write_fifo()

    exit(0)

if __name__ == "__main__":
    main()

