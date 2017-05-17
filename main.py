from parser import *
from interpreter import *
from code_generator import *
from os import system

def print_code_as_tac(ast):
    tac_generator = TACGenerator()
    for instr in get_block(ast)[1:]:
        tac = tac_generator.generate(instr)
        print(instr)
        for tinstr in tac:
            print('\t', tinstr)

def get_ast(file_name):
    parser = Parser() 
    program = open(file_name, 'r').read()
    ast = parser.parse(program)
    if not ast:
        exit(0)
    return ast

def run_in_interpreter(ast):
    interpreter = Interpreter()
    interpreter.run_ast(ast)

def write_code(tas_code):
    asm_file = open('stuff/main_asm.asm', 'w')
    runtime = open('stuff/runtime.asm', 'r').read()
    asm_file.write(runtime + tas_code)
    asm_file.close()
    system('make main_asm')




# load AST tree
ast = get_ast('stuff/prog1.pl0')

# Maybe, print AST...
print("========== AST ==========");
#print_ast(ast)

# Get main block of AST
code = get_block(ast)

# Generate TAC from AST
cg = TACGenerator()

print("========== TAC ==========");

if False:
    i = None
    for instr in code[1:]:
        i = cg.generate_expr(instr, True)
        print(i)
        if i != None:
            pass
            #tcv = TACEvaluator()
            #print(tcv.eval(i[0]))
    exit(0)


print("========== ASM ==========");

tas = TACAssembler()

tas.init_variables(get_vars(ast))

if get_procs(ast):
    tas.init_procedures(get_procs(ast))
    for proc in get_procs(ast)[1:]:
        tas.compile_proc(proc)

tas.compile_main(code)

#exit(0)

print(tas.code)
write_code(tas.code)


