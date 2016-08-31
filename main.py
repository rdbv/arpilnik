import sys; sys.dont_write_bytecode = True

from parser import *
from arpilnik import *

from unicorn import *
from unicorn.x86_const import *

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

f_code = \
'''
    a=2+3
'''


def main():
    t = 2
    for line in f_code.split():
        rpn_exp = infix_to_rpn(line)
        print(line, rpn_exp)
    
if __name__ == "__main__":
    main()

