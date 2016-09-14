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

Token = collections.namedtuple('Token', ['type', 'value'])

'''
    Lexer
'''
def lexical_analysis(text):
    pattern = re.compile('|'.join((NUM, VAR, ADD, SUB, MUL, DIV, EQL, LPAREN, RPAREN, WS)))

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

    def __init__(self):
        self.debug = False

    def parse(self, text, line_no):
        self.tokens = lexical_analysis(text)
        self.lexems = [x for x in lexical_analysis(text)]

        self.current_token = None
        self.next_token = None
        self.next_neg = False
        self.line_num = line_no
        self.char_num = 0
        self.fail = False

        self.out = []

        self.pre_validate()
        self.expr()

        if self.fail:
            print("==Parsing Error==")
            exit(0)

        return self.out

    ''' 
        Check is in form
        <var> = <tokens>
    '''
    def pre_validate(self):
        d = self.debug
        self.debug = False
        self.advance()
        self.expect('VAR')
        self.expect('EQL')
        self.debug = d
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
                self.fail = True
            i+=1
        if self.fail:
            exit(0)

    def advance(self):
        self.current_token, self.next_token = self.next_token, next(self.tokens, None)

        if self.current_token:
            self.char_num += len(self.current_token)

        if self.debug:
            print("advance curr=%s, next=%s" % (self.current_token, self.next_token))

    def accept(self, token_type, f):
        if self.debug:
            pass
            #print("accept %s from %s %s" % (token_type, f, self.current_token) )
        if self.next_token and self.next_token.type == token_type:
            self.advance()
            if self.next_neg:
                self.out.pop()
                self.out.append(Token(self.current_token.type, '-' + self.current_token.value))
            else:
                self.out.append(Token(self.current_token.type, self.current_token.value))
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
            print("_expr_")

        if self.accept('SUB', 'EXPR_'):
            self.next_neg = True

        self.term() 
        while self.accept('ADD', 'EXPR') or self.accept('SUB', 'EXPR'):
            self.term()

        return 

    def term(self):
        if self.debug:
            print("_term_")

        self.factor()
        while self.accept('MUL', 'TERM') or self.accept('DIV', 'TERM'):
            self.factor()

        return

    def factor(self):
        if self.debug:
            print("_factor_")

        if self.accept('NUM', 'FACT') or self.accept('VAR', 'FACT'):
            if self.next_neg:
                self.next_neg = False
            return
        elif self.accept('LPAREN', 'FACT'):
            self.expr()
            self.expect('RPAREN')
            return 
        else:
            if self.next_token:
                print("Syntax Error: Expected NUM or VAR or LPAREN, at %d:%d (got '%s')" % 
                        (self.line_num, self.char_num, self.next_token.value))
            else:
                print("Syntax Error: Expected NUM or VAR or LPAREN, at %d:%d (got nothing)" %
                        (self.line_num, self.char_num))
            self.fail = True


LEFT_ASSOC  = 0
RIGHT_ASSOC = 1

operators = {
    '+' : (0, LEFT_ASSOC),
    '-' : (0, LEFT_ASSOC),
    '*' : (1, LEFT_ASSOC),
    '/' : (1, LEFT_ASSOC),
}

def is_operator(token):
    return token.value in operators

def is_assoc(token, assoc):
    if not is_operator(token):
        raise ValueError('Invalid token: %s' % token.value)
    return operators[token.value][1] == assoc

def cmp_prec(token1, token2):
    if not is_operator(token1) or not is_operator(token2):
        raise ValueError('Invalid tokens: %s %s' % (token1.value, token2.value) )
    return operators[token1.value][0] - operators[token2.value][0]

def infix_to_rpn(tokens):
    out = []
    stack = []
    for token in tokens:
        # If token is operator
        if is_operator(token):
            # Then pop operators from top of the stack
            while len(stack) != 0 and is_operator(stack[-1]):
                if (is_assoc(token, LEFT_ASSOC) 
                and cmp_prec(token, stack[-1]) <= 0) or (is_assoc(token, RIGHT_ASSOC)
                and cmp_prec(token, stack[-1]) < 0):
                    out.append(stack.pop())
                    continue
                break
            # If stack is empty
            stack.append(token)
        elif token.value == '(':
            # If token is ( then, just append to stack
            stack.append(token)
        elif token.value == ')':
            while len(stack) != 0 and stack[-1].value != '(':
                out.append(stack.pop())
            stack.pop()
        else:
            # Token is digit or some other symbol (currentlly not supported)
            out.append(token)

    # Pop all tokens from stack to output
    while len(stack) != 0:
        out.append(stack.pop())
    return out

