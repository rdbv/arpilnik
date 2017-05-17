from collections import OrderedDict, Iterable
from parser import *

def is_register(n):
    if len(n) > 1:
        return n[1] == 't';
    else:
        return None

def is_memory(n):
    if len(n) > 1:
        return n[1] == 's';
    else:
        return None


class TACEvaluator:
    def __init__(self):
        self.regs = {}

    def eval(self, tac):
        li = None
        for i in tac:
            if len(i) == 2:
                self.regs[i[0]] = self.solve_symbol(i[1])
            else:
                li = self.regs[i[0]] = self.op(self.solve_symbol(i[1]), self.solve_symbol(i[3]), i[2])
            print(self.regs)
        return self.regs[i[0]]

    def solve_symbol(self, s):
        if s.isdigit():
            return int(s)
        else:
            return int( self.regs[s] )

    def op(self, a, b, op):
        if op == '+': return a+b
        if op == '-': return a-b
        if op == '*': return a*b
        if op == '/': return a/b

class TACGenerator:

    ''' 
        Generate very unoptimal three address code from instruction 
    '''

    tmp_regs = ['#t%d' % i for i in range(0, 4)]

    used_regs = OrderedDict( ('#t%d' % i, False) for i in range(0, 4) )
    used_spills = OrderedDict( ('#s%d' % i, False ) for i in range(0, 8) )
    
    def __init__(self):
        pass

    # Called for every 'real' line of code
    def generate_expr(self, expr, reset_reuse = True):
        if(expr[0] == 'PRINT'):
            return None

        # Generate RPN 
        code_rpn = self.flatten(self.eval_expr(expr))

        # TAC from RPN
        return self.generate_tac(code_rpn, reset_reuse)
   
    ''' 
        Based on RPN evaluating generation of TAC
    '''
    def generate_tac(self, code_rpn, reset_reuse = True):
        tmp_stack = []
        code_tac = []

        # Iterate over RPN tokens
        for token in code_rpn:

            # Get free memory place
            # if register is free, then register
            # else - get some memory
            tmp_val = self.get_data()

            # Arithmetric operation
            if token in ['+', '-', '*', '/']:

                # Flag reg/mem as already used
                if is_memory(tmp_val): 
                    self.used_spills[tmp_val] = True
                elif is_register(tmp_val): 
                    self.used_regs[tmp_val] = True

                # Create TAC instruction
                a, b = tmp_stack.pop(), tmp_stack.pop()
                code_tac.append([tmp_val, b, token, a])

                # Result of last operation will be stored there, so.. 
                # add to stack
                tmp_stack.append(tmp_val)

                # Flag reg/mem as free
                self.flag_data_unused(a)
                self.flag_data_unused(b)

            # Negation
            elif token[0] == '!':
                if token[1] == '-':
                    code_tac.append([tmp_val, '-', tmp_stack.pop()])
                    if is_memory(tmp_val):
                        self.used_spills[tmp_val] = True
                    elif is_register(tmp_val):
                        self.used_regs[tmp_val] = True
                    tmp_stack.append(tmp_val)
            # Variable
            else:
                tmp_stack.append(token)
       
        # Assignment, numval on topstack
        if len(tmp_stack) == 1 and tmp_stack[-1][0] != '#':
            code_tac.append([self.tmp_regs[0], tmp_stack.pop()])
            tmp_stack.append(self.tmp_regs[0])

        #print(code_rpn)
        #for l in code_tac:
        #    print("    ", l)
        
        # Return TAC and register where result are stored
        return [code_tac, tmp_stack.pop()]

    '''
        Check is register available,
        If not - then choose memory, but regs are faster
    '''
    def get_data(self):

        if self.free_regs_available():
            data = self.used_regs;
        else:
            data = self.used_spills;

        for r, v in data.items():
            if not v:
                return r

        ip = InfoPrinter()
        ip.error("Can't allocate %s")
        exit(0)

    '''
        Just check is any register available
    '''
    def free_regs_available(self):
        for r, v in self.used_regs.items():
            if not v:
                return True
        return False

    '''
        Flag that we don't use mem/reg
    '''
    def flag_data_unused(self, data):
        if is_register(data):
            self.used_regs[data] = False
            return
        elif is_memory(data):
            self.used_spills[data] = False
            return
        # Digit


    ''' 
        RPN Generator Part 
        Recursive-descent style parsing
    '''

    def flatten(self, x):
        if isinstance(x, Iterable) and not isinstance(x, str):
            return [a for i in x for a in self.flatten(i)]
        else:
            return [x]

    def evaluate(self, node):
        if node[0] == 'TERM': return self.eval_term(node)
        if node[0] == 'EXPR': return self.eval_expr(node)
        if node[0] == 'NUM' or node[0] == 'VAR':
            return node[1]

    def eval_term(self, node):
        a = []
        a.append(self.evaluate(node[1]))
        for term in node[2:]:
            a.append(self.evaluate(term[1]))
            if term[0] == 'MUL': a.append('*')
            if term[0] == 'DIV': a.append('/')
        return a

    def eval_expr(self, node):
        a = []

        a.append(self.evaluate(node[2]))

        for term in node[3:]:
            a.append(self.evaluate(term[1]))
            if term[0] == 'ADD': a.append('+')
            if term[0] == 'SUB': a.append('-')

        # Flip sign
        if node[1] == 'MINUS':
            a.append('!-')

        return a


