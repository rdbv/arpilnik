import sys; sys.dont_write_bytecode = True

from parser import *
from arpilnik import *

#from unicorn import *
#from unicorn.x86_const import *

# main

def step(emu, addr, size, user_data):
    rip = emu.reg_read(UC_X86_REG_RIP)
    rax = emu.reg_read(UC_X86_REG_RAX)
    rbx = emu.reg_read(UC_X86_REG_RBX)
    rcx = emu.reg_read(UC_X86_REG_RCX)
    rdx = emu.reg_read(UC_X86_REG_RDX)

    if rip == user_data:
        emu.emu_stop()

    print("RAX:%x\tRBX:%x\tRCX:%x\tRDX:%x\tRIP:%x" % (rax, rbx, rcx, rdx, rip) )
    
    #raw_input()

def test_emu(code):
    ADDR = 0x80000000

    emu = Uc(UC_ARCH_X86, UC_MODE_64)

    emu.mem_map(ADDR, 2 * 1024 * 1024)
    emu.mem_write(ADDR, code)
   
    emu.reg_write(UC_X86_REG_RSP, ADDR + 0x300)

    emu.hook_add(UC_HOOK_CODE, step, ADDR + len(code))
 
    emu.emu_start(ADDR, 3)

def get_test_exps():
    for exp in sample_exp_list:
        os = ""
        out = infix_to_rpn(exp)
        for t in out:
            os += t + " "
        print(os)

OBJDUMP_CMD = b"clear;objdump -b binary -m i386:x64-32 -M intel -D main \
        --start-address=0xb0 | more"

R2_CMD = b"clear;r2 -d main -c 'pd 25 @ entry0' -q"

def write_fifo():
    fifo = open("stuff/in0.fifo", "wb")
    fifo.write(R2_CMD)
    fifo.close()


f_code = [
    "c=2",

]

def main():
    exp = "0 - 2"
    syn_anal = Syntax_Analyzer()
    out = syn_anal.parse(exp)
    print(out)

    pass

    '''
    cg = Code_Generator_x86_64()
    cg.init_binary()
    for line in f_code:
        cg.compile_line(infix_to_rpn(line))

    cg.add_exit_seq()

    f = open("stuff/main","wb")
    f.write(cg.get_code())
    write_fifo()
    '''

if __name__ == "__main__":
    main()

