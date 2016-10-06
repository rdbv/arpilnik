import re
import collections
from bisect import bisect

Token = collections.namedtuple('Token', ['type', 'value'])

''' 
    Just lexer, splitting input stream into tokens
    a = 2 -> [Token('VARNAME', a), Token('EQL', =), Token('NUM', 2)]
'''
class Lexer:

    tokens_regexp = [
         # Keywords
         r'(?P<CONST_KEYWORD>\bconst\b)', 
         r'(?P<VAR_KEYWORD>\bvar\b)', 
         r'(?P<PROC_KEYWORD>\bproc\b)', 
         r'(?P<CALL_KEYWORD>\bcall\b)', 
         r'(?P<BEGIN_KEYWORD>\bbegin\b)', 
         r'(?P<END_KEYWORD>\bend\b)', 
         r'(?P<IF_KEYWORD>\bif\b)', 
         r'(?P<THEN_KEYWORD>\bthen\b)', 
         r'(?P<WHILE_KEYWORD>\bwhile\b)', 
         r'(?P<DO_KEYWORD>\bdo\b)', 
         r'(?P<BLANK_KEYWORD>\bblank\b)', 

         # Other symbols
         r'(?P<COMMENT_BEGIN>\/\*)',
         r'(?P<COMMENT_END>\*\/)',
         r'(?P<SEMICOLON>;)', 
         r'(?P<COMMA>,)', 
         r'(?P<SET_VAR>:=)', 
         r'(?P<EQL_CMP>==)', 
         r'(?P<LT_CMP><)',
         r'(?P<NUM>\d+)', 
         r'(?P<VARNAME>[_A-Za-z][_a-zA-Z0-9]*)', 
         r'(?P<ADD>\+)', 
         r'(?P<SUB>-)', 
         r'(?P<MUL>\*)', 
         r'(?P<DIV>/)', 
         r'(?P<EQUAL>=)', 
         r'(?P<LPAREN>\()', 
         r'(?P<RPAREN>\))', 
         r'(?P<WS>\s+)',
    ]

    def lex(self, text):
        pattern = re.compile('|'.join(self.tokens_regexp))
        scanner = pattern.scanner(text)
       
        last_token = None
        comment = False
        for m in iter(scanner.match, None):
            token = Token(m.lastgroup, m.group())
            last_token = token

            # Skip c-style comments 
            # /* ololololoolol */
            if token.type == 'COMMENT_BEGIN':
                comment = True
                continue

            if comment:
                if token.type == 'COMMENT_END':
                    comment = False
                continue

            if token.type != 'WS':
                yield token
            
''' Help class for printing info in colors '''
class InfoPrinter:
    ENDCOLOR = '\033[0m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    fail = False

    def warning(self, text):
        print(self.YELLOW + "[WARNING] " + self.ENDCOLOR + text)

    def error(self, *args):
        fail = True
        print(self.RED + "[ERROR] " + self.ENDCOLOR, end='')
        for arg in args: print(arg, end=' ')
        print()
    
    def ok(self, text):
        print(self.GREEN + "[OK] " + self.ENDCOLOR + text)

''' Recursive descent parser for PL/0 language '''
class Parser:
    def __init__(self):
        self.ip = InfoPrinter()
        self.lexer = Lexer()
        self.fail = False

    def parse(self, text):
        self.char_no = 0
        self.current_token = None
        self.next_token = None
        self.nl_pos = self.get_new_line_positions(text)
        self.iter = self.lexer.lex(text)
        self.advance()
        return self.program()

    def get_new_line_positions(self, text):
        return [i for i, ltr in enumerate(text) if ltr == '\n']

    def get_line_number(self):
        return bisect(self.nl_pos, self.char_no) + 1

    def advance(self):
        if self.next_token:
            self.char_no += len(self.next_token.value)
        self.current_token, self.next_token = self.next_token, next(self.iter, None)
      
    def accept(self, token):
        if self.next_token and self.next_token.type == token:
            self.advance()
            return True
        return False
    
    def expect(self, token):
        if not self.accept(token):
            self.fail = True
            self.ip.error("Expected", token, "got", self.next_token, "at line", self.get_line_number()) 

    def factor(self):
        if self.accept('VARNAME'):
            return ('VAR', self.current_token.value)
        elif self.accept('NUM'):   
            return ('NUM', self.current_token.value)
        elif self.accept('LPAREN'):
            exp = self.expression()
            self.expect('RPAREN')
            return exp
        else:
            self.ip.error("Parsing error in factor at line", self.get_line_number())
            self.advance()

    def term(self):
        out = ['TERM']

        out.append(self.factor())
        while self.accept('MUL'): out.append(['MUL', self.factor()])
        while self.accept('DIV'): out.append(['DIV', self.factor()])

        return out

    def expression(self):
        out = ['EXPR', None]

        # Maybe negative number?
        while self.accept('SUB'):
            out[1] = 'MINUS'

        out.append(self.term())
        while self.accept('ADD'): out.append(['ADD', self.term()])
        while self.accept('SUB'): out.append(['SUB', self.term()])

        return out

    def condition(self):
        cond = ['CONDITION']
        cond.append(self.expression())
        if self.accept('EQL_CMP'):
            cond.append('EQL_CMP')
            cond.append(self.expression())
        elif self.accept('LT_CMP'):
            cond.append('LT_CMP')
            cond.append(self.expression())
        else:
            self.ip.error("Condition error at", self.get_line_number())
            self.advance()
        return cond

    def statement(self):
        out = []
        if self.accept('BLANK_KEYWORD'):
            out.append('BLANK')
        elif self.accept('VARNAME'):
            out.append("SET")
            out.append(self.current_token.value)
            self.expect('SET_VAR')
            out.append(self.expression())
        elif self.accept('CALL_KEYWORD'):
            out.append('CALL')
            out.append(self.next_token.value)
            self.expect('VARNAME')
        elif self.accept('BEGIN_KEYWORD'):
            out.append('BEGIN')
            while True:
                out.append(self.statement())
                if not self.accept('SEMICOLON'):
                    break
            self.expect('END_KEYWORD')
        elif self.accept('IF_KEYWORD'):
            out.append('IF')
            out.append(self.condition())
            self.expect('THEN_KEYWORD')
            out.append(self.statement())
        elif self.accept('WHILE_KEYWORD'):
            out.append('WHILE')
            out.append(self.condition())
            self.expect('DO_KEYWORD')
            out.append(self.statement())
        else:
            self.ip.error("Statement error at", self.get_line_number())
            self.advance()
        return out

    def sub_block_constants(self):
        consts = ['CONSTANTS']
    
        if self.accept('CONST_KEYWORD'):
            while True:
                self.expect('VARNAME')
                const_name = self.current_token.value
                self.expect('EQUAL')
                self.expect('NUM')
                const_value = self.current_token.value
                consts.append((const_name, const_value))
                if not self.accept('COMMA'):
                    break
            self.expect('SEMICOLON')
        
        if len(consts) > 1:
            return consts
        else:
            return None

    def sub_block_vars(self):
        vars = ['VARIABLES']

        if self.accept('VAR_KEYWORD'):
            while True:
                self.expect('VARNAME')
                vars.append(self.current_token.value)
                if not self.accept('COMMA'):
                    break
            self.expect('SEMICOLON')

        if len(vars) > 1:
            return vars
        else:
            return None
    
    def sub_block_procedures(self):
        procs = ['PROCEDURES']

        while self.accept('PROC_KEYWORD'):
            self.expect('VARNAME')
            name = self.current_token.value
            self.expect('SEMICOLON')
            procs.append(['PROCEDURE', name, self.block()])
            self.expect('SEMICOLON') 

        if len(procs) > 1:
            return procs
        else:
            return None

    def block(self):
        block = ['BLOCK']

        block.append(self.sub_block_constants())
        block.append(self.sub_block_vars())
        block.append(self.sub_block_procedures())

        block.append(self.statement())
        
        return block

    def program(self):
        return ['PROGRAM', self.block()]


''' 
    Pretty printing of abstract syntax tree
    Used for debugging
'''
def print_ast(l, sp = 0):
    if l == None: return
    if type(l) in (list, tuple):
        print_ast(l[0], sp)
        for val in l[1:]:
            print_ast(val, sp + 2)
    else:
        print(' ' * sp + l)
        
