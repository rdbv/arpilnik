class Block:
    def __init__(self, node):
        self.constants = {}
        self.variables = {}
        self.procedures = {}
        
        self.set_constants(node[1])
        self.set_variables(node[2])
        self.set_procedures(node[3])
        self.begin = node[4]

    def set_constants(self, node):
        if node:
            for name, value in node[1:]:
                self.constants[name] = value

    def set_variables(self, node):
        if node:
            for name in node[1:]:
                self.variables[name] = 0

    def set_procedures(self, node):
        if node:
            for procedure in node[1:]:
                self.procedures[procedure[1]] = procedure[2]

    def exist(self, name, type):
        if type == 'VAR':   return name in self.variables
        if type == 'CONST': return name in self.constants
        if type == 'PROC':  return name in self.procedures
        assert False

class Interpreter:
    stack = []

    def run_ast(self, ast):
        self.block(ast[1])

    def push(self, node):
        self.stack.append(Block(node))

    def pop(self):
        return self.stack.pop()
    
    def top(self):
        return self.stack[-1]
   
    def search_on_stack(self, val, type):
        for i, v in enumerate(reversed(self.stack)): 
            if v.exist(val, type): 
                return i
        return None

    def block(self, node):
        self.push(node)
        self.begin(self.top().begin)
        self.pop()
    
    def begin(self, node):
        # If it is only one instruction
        # Without 'BEGIN' block
        if node[0] != 'BEGIN': node = ['BEGIN', node]
        for instr in node[1:]:
            if instr[0] == 'SET':   self.set(instr)
            if instr[0] == 'WHILE': self.do_while(instr)
            if instr[0] == 'CALL':  self.call(instr)
            if instr[0] == 'IF':    self.if_statement(instr)
            if instr[0] == 'BLANK': self.blank()
            if instr[0] == 'PRINT': self.print(instr)

    def do_while(self, node):
        cond, body = node[1], node[2]
        while self.if_compare(cond):
            self.begin(body)
   
    def if_statement(self, node):
        cond, body = node[1], node[2]
        if self.if_compare(cond):
            self.begin(body)

    def if_compare(self, node):
        a, compar, b = self.evaluate(node[1]), node[2], self.evaluate(node[3])
        if compar == 'EQL_CMP': return a == b
        if compar == 'NEQ_CMP': return a != b
        if compar == 'LTE_CMP': return a <= b
        if compar == 'GTE_CMP': return a >= b
        if compar == 'GT_CMP' : return a >  b
        if compar == 'LT_CMP' : return a <  b
        assert False

    def blank(self):
        print("---Debug Frame---")
        print(self.top().variables, self.top().constants)
        print("-----------------")

    def print(self, node):
        v = self.evaluate(['VAR', node[1]])
        print(node[1], v)

    def call(self, node):
        name = node[1]
        proc_frame = self.search_on_stack(name, 'PROC')
        proc = self.stack[-1-proc_frame].procedures[name]
        self.block(proc)

    def set(self, node):
        name = node[1]
        stack_frame = self.search_on_stack(name, 'VAR')
        self.stack[-1 - stack_frame].variables[name] = self.eval_expr(node[2])

    def evaluate(self, node):
        if node[0] == 'TERM': return self.eval_term(node)
        if node[0] == 'EXPR': return self.eval_expr(node)
        if node[0] == 'NUM' : return int(node[1])
        if node[0] == 'VAR' : 
            name = node[1]
            var_stack = self.search_on_stack(name, 'VAR')
            const_stack = self.search_on_stack(name, 'CONST')
            if var_stack is not None:   return int(self.stack[-1-var_stack].variables[name])
            if const_stack is not None: return int(self.stack[-1-const_stack].constants[name]) 
            raise RuntimeError('Reference %s don\'t exists!' % name)
        assert False

    def eval_term(self, node):
        a = self.evaluate(node[1])
        for term in node[2:]:
            b = self.evaluate(term[1])
            if term[0] == 'MUL': a *= b
            if term[0] == 'DIV': a /= b
            if term[0] == 'MOD': a %= b
        return a

    def eval_expr(self, node):
        a = self.evaluate(node[2])
        for term in node[3:]:
            b = self.evaluate(term[1])
            if term[0] == 'ADD': a += b
            if term[0] == 'SUB': a -= b
        if node[1] == 'MINUS':
            a *= -1
        return a
