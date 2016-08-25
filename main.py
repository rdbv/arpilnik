from parser import *
from binary_stuff import *

# main

sample_exp_list = [
        "a*10+15",
        "dupa*10+5+fun(4)",
        "10+24*c-17*(d*24+8+g)",
        "24+a*n/2-7"
    ]

def get_test_exps():
    for exp in sample_exp_list:
        os = ""
        out = infix_to_rpn(exp)
        for t in out:
            os += t + " "
        print(os)

OBJDUMP_CMD = b"clear;objdump -b binary -m i386:x64-32 -M intel -D main \
        --start-address=0x78 | more"

def write_fifo():
    fifo = open("in0.fifo", "wb")
    fifo.write(OBJDUMP_CMD)
    fifo.close()

def main():
    infix_exp = "2+5-3"
    rpn_exp = infix_to_rpn(infix_exp)

    print(rpn_exp, compute_rpn_val(rpn_exp))
    
    gen = Code_Generator_x86_64()
    gen.init_binary()
    gen.compile_exp(rpn_exp)

    out_file = open("main", "wb")
    out_file.write(gen.get_code() + b'\x90\x90')
    
    write_fifo()


if __name__ == "__main__":
    main()

