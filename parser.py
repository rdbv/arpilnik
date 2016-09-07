import re
import collections

# Lexems regexps
NUM     = r'(?P<NUM>\d+)'
VAR     = r'(?P<VAR>[_A-Za-z][_a-zA-Z0-9]*)'

#FUN     = r'(?P<FUN>[a-zA-Z0-9]+\([^\)]*\)(\.[^\)]*\))?)'

ADD     = r'(?P<ADD>\+)'
SUB     = r'(?P<SUB>-)'
MUL     = r'(?P<MUL>\*)'
DIV     = r'(?P<DIV>/)'
EQL     = r'(?P<EQL>=)'

LPAREN  = r'(?P<LPAREN>\()'
RPAREN  = r'(?P<RPAREN>\))'

WS      = r'(?P<WS>\s+)'



def lexical_analysis(text):
    pattern = re.compile('|'.join((NUM, VAR, ADD, SUB, MUL, DIV, EQL, LPAREN, RPAREN, WS)))
    Token = collections.namedtuple('Token', ['type', 'value'])

    scanner = pattern.scanner(text)
   
    last_token = None
    for m in iter(scanner.match, None):
        token = Token(m.lastgroup, m.group())
        last_token = token

        if token.type != 'WS':
            yield token

'''
    Syntactic parser, recursive descent
'''

class Parser:

    def parse(self, text, line_no):
        self.tokens = lexical_analysis(text)
        self.lexems = [x for x in lexical_analysis(text)]

        self.current_token = None
        self.next_token = None
        self.next_neg = False
        self.line_num = line_no
        self.char_num = 0
        self.debug = False
        self.fail = False
        self.out = []

        self.pre_validate()
        v = self.expr()

        if self.fail:
            return None

        return v

    ''' 
        Check is in form
        <var> = <tokens>
    '''
    def pre_validate(self):
        self.advance()
        self.expect('VAR')
        self.expect('EQL')
        self.validate_lexems()

    '''
        Detect 'NUM' 'NUM', 'NUM' 'VAR', 'NUM' 'LPAREN' sequences
    '''
    def validate_lexems(self):
        bad_seq = ['NUM', 'VAR', 'LPAREN']
        if len(self.lexems) <= 3: return
        for i in range(2, len(self.lexems) - 1):
            current_lex, next_lex = (self.lexems[i], self.lexems[i+1])
            if current_lex.type in bad_seq[0:1] and next_lex.type in bad_seq:
                print("NUM/VAR/LPAREN after NUM/VAR")
            i+=1

    def advance(self):
        self.current_token, self.next_token = self.next_token, next(self.tokens, None)

        if self.current_token:
            self.char_num += len(self.current_token)

        if self.debug:
            print("advance curr=%s, next=%s" % (self.current_token, self.next_token))

    def accept(self, token_type, f):
        if self.debug:
            print("accept %s from %s %s" % (token_type, f, self.current_token) )
        if self.next_token and self.next_token.type == token_type:
            self.advance()
            return True
        else:   
            return False

    def expect(self, token_type):
        if not self.accept(token_type, 'EXPE'):
            print("Expected %s at %d:%d (got %s)" % (token_type, self.line_num, 
                self.char_num, self.next_token))
            self.fail = True
        
    def expr(self):
        if self.debug:
            print("EXPR")

        if self.accept('SUB', 'EXPR_'):
            self.next_neg = True

        expr_val = self.term()
        while self.accept('ADD', 'EXPR') or self.accept('SUB', 'EXPR'):
            op = self.current_token.type
            if op == 'ADD':
                expr_val += self.term()
            elif op == 'SUB':
                expr_val -= self.term()
            else:
                print("Syntax error - expected + or -")

        return expr_val        

    def term(self):
        if self.debug:
            print("TERM")

        val = self.factor()

        while self.accept('MUL', 'TERM') or self.accept('DIV', 'TERM'):
            op = self.current_token.type
            if op == 'MUL':
                val *= self.factor()
            elif op == 'DIV':
                val /= self.factor()
            else:
                print("Syntax error - expected * or /")

        return val

    def factor(self):
        if self.debug:
            print("FACT")

        if self.accept('NUM', 'FACT'):
            if self.next_neg:
                self.next_neg = False
                return -int(self.current_token.value)
            else:
                return int(self.current_token.value)
        elif self.accept('LPAREN', 'FACT'):
            val = self.expr()
            self.expect('RPAREN')
            return val
        else:
            print("Syntax Error: Expected NUM or VAR or LPAREN, at %d:%d (got '%s')" % 
                    (self.line_num, self.char_num, self.next_token.value))
            return 0


