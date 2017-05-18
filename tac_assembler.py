from collections import OrderedDict, Iterable
from parser import *
from tac_generator import *

def is_assignment(instr):
    return len(instr) == 2;

def is_negation(instr):
    return len(instr) == 3;

class TACAssembler:

    registers = {'#t0' : 'eax', '#t1' : 'ebx', '#t2' : 'ecx', '#t3' : 'edx'}

    spills = OrderedDict()

    code, data = '', '';

    TCG = TACGenerator()

    if_count, while_count = 0, 0
    if_stack, while_stack, var_stack = [], [], []
    procedures = []

    def __init__(self):
        pass

    def compile(self, node):
        if node[0] == 'SET':
            return self.compile_set(node)
        if node[0] == 'IF':
            return self.compile_if(node)
        if node[0] == 'WHILE':
            return self.compile_while(node)
        if node[0] == 'PRINT':
            return self.compile_print(node)
        if node[0] == 'CALL':
            return self.compile_call(node)
        assert False

    def compile_main(self, code):
        self.code += '\n_start:\n'

        for instr in code[1:]:
            self.compile(instr)

        self.emit('call exit')
        self.emit_spill_variables()
        self.emit_global_variables()


    def compile_proc(self, node):
        self.init_variables(node[2][2])
        begin_node = node[2][4]

        # procedure name
        self.code += ('proc_' + node[1] + ':\n')
        
        # stack frame

        if len(self.var_stack[-1]):
            self.emit('push ebp')
            self.emit('mov ebp, esp')
            self.emit('sub esp, %d' % (len(self.var_stack[-1]) * 4) )

        for instr in begin_node[1:]:
            self.compile(instr)

        if len(self.var_stack[-1]):
            self.emit('add esp, %d' % (len(self.var_stack[-1]) * 4) )
            self.emit('pop ebp')

        self.emit('ret')
        self.code += '\n'
        self.var_stack.pop()

    def compile_while(self, node):
        lhs, rhs, op, body = node[1][1], node[1][3], node[1][2], node[2]
        self.while_count += 1
        self.while_stack.append(self.while_count)

        self.emit('; WHILE ')

        self.code += 'W%d:\n' % self.while_stack[-1]

        left_reg = self.compile_expr(lhs)
        self.emit('mov [%s], %s' % (self.get_spill_var('#s0'), self.registers[left_reg]) )

        right_reg = self.compile_expr(rhs)
        self.emit('cmp [%s], %s' % (self.get_spill_var('#s0'), self.registers[right_reg]))
        self.emit('%s E%d' % (self.get_cmp_not(op), self.while_count))
       
        self.code += 'B%d:\n' % (self.while_stack[-1]);

        for instr in body[1:]:
            self.compile(instr)

        self.emit('jmp W%d' % self.while_stack[-1])

        self.code += 'E%d:\n' % self.while_stack[-1]

        self.emit('; INEND ')

    def compile_if(self, node):
        lhs, rhs, op, body = node[1][1], node[1][3], node[1][2], node[2]
        self.if_count += 1
        self.if_stack.append(self.if_count)

        if body[0] != 'BEGIN':
            body = ['BEGIN', body]
       
        self.emit('; IF ')

        left_reg = self.compile_expr(lhs)
        self.emit('mov [%s], %s' % (self.get_spill_var('#s0'), self.registers[left_reg]) )

        right_reg = self.compile_expr(rhs)
        self.emit('cmp [%s], %s' % (self.get_spill_var('#s0'), self.registers[right_reg]))
        self.emit('%s L%d' % (self.get_cmp_not(op), self.if_stack[-1]))

        self.emit('; ELSE ')

        for instr in body[1:]:
            self.compile(instr)

        self.code += 'L%d:\n' % (self.if_stack[-1])
        self.if_stack.pop()

    def get_cmp_not(self, cmp):
        if cmp == 'NEQ_CMP': return 'je'
        if cmp == 'EQL_CMP': return 'jne'
        if cmp == 'GT_CMP': return 'jle'
        if cmp == 'LT_CMP': return 'jge'
        if cmp == 'GTE_CMP' : return 'jl'
        if cmp == 'LTE_CMP' : return 'jg'


    '''
        Compile equation to TAC and save in variable
    '''
    def compile_set(self, node):
        var = node[1]
        expr = node[2]
        final_reg = self.compile_expr(expr)

        if is_memory(final_reg):
            self.emit('mov esi, %s' % self.get_spill_var(final_reg) )
            self.emit('mov %s, esi' % (self.resolve_term(var)) )
        elif is_register(final_reg):
            self.emit('mov %s, %s' % ( self.resolve_term(var), self.registers[final_reg]))

    '''
        Load variable to eax and print with function from runtime
    '''
    def compile_print(self, node):
        var = node[1]
        self.emit('mov eax, %s ; VAR_ARG %s' % ((self.resolve_term(var)), var))
        self.emit('call print_num_nl')

    def compile_call(self, node):
        proc_name = node[1]
        self.emit('call proc_%s' % proc_name)

    ''' 
        Compile expression and return register with value
    '''
    def compile_expr(self, expr):
        # Get TAC data
        expr_tac = self.TCG.generate_expr(expr)

        # Result will be stored in this place
        final_reg = expr_tac[1]
        
        # Go throught tokens        
        for instr in expr_tac[0]:

            # Destination, first value in TAC
            if is_register(instr[0]):
                dst = self.registers[instr[0]]
            elif is_memory(instr[0]):
                dst = 'edi'

            if is_assignment(instr):
                # Numeric value
                r1 = instr[1]
                self.emit('mov %s, %s' % (dst, self.resolve_term(r1)))
            elif is_negation(instr):
                op, r1 = instr[1], instr[2]
                self.emit('mov %s, %s' % (dst, self.resolve_term(r1)))
                self.emit('neg %s' % (dst))
            else:
                op = instr[2]
                r1, r2 = self.resolve_term(instr[1]), self.resolve_term(instr[3]) 

                # Load
                if op != '/':
                    self.emit('mov %s, %s' % (dst, r1))

                # Compute
                if op == '+': 
                    self.emit('add %s, %s' % (dst, r2))
                if op == '-': 
                    self.emit('sub %s, %s' % (dst, r2))
                if op == '*': 
                    self.emit('imul %s, %s' % (dst, r2))

                # Dividing is bit tricky 
                if op == '/':
                    self.emit('mov esi, %s' % (r2))
                    self.emit('mov eax, %s' % (r1))
                    # TODO
                    # ...bug...
                    self.emit('xor edx, edx')
                    self.emit('cdq')
                    self.emit('idiv esi')
                    self.emit('mov %s, eax' % (dst), comment = 'r2')

                if is_memory(instr[0]):
                    self.emit('mov [%s], edi' % self.get_spill_var(instr[0]))

        return final_reg

    def emit(self, code, indent = 1, comment = '', t = 'code'):
        if t == 'code':
            self.code += ('    ' * indent) + code + ';  ' + comment + '\n'
        if t == 'data':
            self.data += ('    ' * indent) + code + ';  ' + comment + '\n'

    def init_variables(self, var_node):
        self.var_stack.append(OrderedDict())
        if var_node:
            for i, var in enumerate(var_node[1:]):
                self.var_stack[-1][var] = -4 * i

    '''
        Save procedures names
    '''
    def init_procedures(self, proc_node):
        if proc_node:
            for proc in proc_node[1:]:
                self.procedures.append(proc[1])

    ''' 
        Check in function variables, and main function variables
    '''
    def search_variable(self, var):
        # Search variable in our stack (can be main)
        if var in self.var_stack[-1]:
            if len(self.var_stack) != 1:
                # Not main
                return 'dword [ebp-%s]' % (-1* (self.var_stack[-1][var] - 4) )
            else:
                #  Main, all vars in main range are global
                return 'dword [%s]' % ('global_var_' + var)
        elif var in self.var_stack[0]:
            # Not in our stack, so global
            return 'dword [%s]' % ('global_var_' + var)
        else:
            print("NIEMA\n")
            exit(0)

    '''
        Return register name, spill var name, or variable offset/global name
    '''
    def resolve_term(self, r1):
        if not r1.isdigit():
            if r1[0] == '#':
                if r1[1] == 't':
                    return self.registers[r1]
                if r1[1] == 's':
                    return 'dword [%s]' % self.get_spill_var(r1)
            else:
                return self.search_variable(r1)
        else:
            return r1

    '''
        Check is in spills list, if not, just add
    '''
    def get_spill_var(self, r1):
        if r1 not in self.spills:
            self.spills[r1] = 'spill_var_%s' % r1[2:]
        return self.spills[r1]

    ''' 
        Data
    '''
    def emit_spill_variables(self):
        self.code += '\nsection .data\n'
        for s in self.spills:
            self.emit( ('spill_var_%s' % s[2:]) + ' dd 0')
    
    def emit_global_variables(self):
        for s in self.var_stack[-1]:
            self.emit( ('global_var_%s' % s) + ' dd 0')

