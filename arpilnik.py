#!/usr/bin/python3
from parser import *
from tac_generator import *
from tac_assembler import *
from os import system
from argparse import *
import sys

def get_ast(file_name):
    parser = Parser() 
    program = open(file_name, 'r').read()
    ast = parser.parse(program)
    if not ast:
        exit(0)
    return ast

def compile(args):
    # Load program as AST
    ast = get_ast(args['src_name'])
    code = get_block(ast)
    cg = TACGenerator()

    tas = TACAssembler()
    tas.init_variables(get_vars(ast))

    # Compile procedures
    if get_procs(ast):
        tas.init_procedures(get_procs(ast))
        for proc in get_procs(ast)[1:]:
            tas.compile_proc(proc)

    # Compile main
    tas.compile_main(code)

    rt = open('runtime.asm', 'r').read()

    asm_file = open(args['out_name'], 'w')
    asm_file.write(rt + tas.code)
    asm_file.close()

    if not args['asm']:
        system('nasm -f elf32 ' + args['out_name'] + " -o " +args['out_name'] + "_bin")
        system('ld -m elf_i386 ' + args['out_name'] + "_bin" + " -o " + args['out_name'])

    print("Compiled with no errors, i think...")

argp = ArgumentParser()
argp.add_argument("-s", help="Source filename", dest="src_name")
argp.add_argument("-o", help="Output filename", dest="out_name")
argp.add_argument("-asm", help="Don't assembly, just compile", dest="asm", action="store_true")
args = vars(argp.parse_args())
if not args['src_name'] or not args['out_name']:
    argp.print_help()
    sys.exit(0)

compile(args)

sys.exit(0)
