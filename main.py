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

def main():
    get_test_exps()
    pass
    #out = infix_to_rpn(exp)
    #print(out)


if __name__ == "__main__":
    main()

