from parser import *
from interpreter import *

program = open('stuff/prog.pl0', 'r').read()

parser = Parser()
interpreter = Interpreter()

ast = parser.parse(program)

print_ast(ast)
#print(ast)

print(" ==================== ")
interpreter.run_ast(ast)







