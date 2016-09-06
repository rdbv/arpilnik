import re
import collections

# Lexems regexps
NUM     = r'(?P<NUM>-?\d+)'
VAR     = r'(?P<VAR>-?[_A-Za-z][_a-zA-Z0-9]*)'
FUN     = r'(?P<FUN>-?[a-zA-Z0-9]+\([^\)]*\)(\.[^\)]*\))?)'

ADD     = r'(?P<ADD>\+)'
SUB     = r'(?P<SUB>-)'
MUL     = r'(?P<MUL>\*)'
DIV     = r'(?P<DIV>/)'

LPAREN  = r'(?P<LPAREN>\()'
RPAREN  = r'(?P<RPAREN>\))'

WS      = r'(?P<WS>\s+)'

def lexical_analysis(text):
    pattern = re.compile('|'.join((NUM, FUN, VAR, ADD, SUB, MUL, DIV, LPAREN, RPAREN, WS)))
    Token = collections.namedtuple('Token', ['type', 'value'])

    scanner = pattern.scanner(text)

    for m in iter(scanner.match, None):
        token = Token(m.lastgroup, m.group())

        if token.type != 'WS':
            yield token


''' 
    Recursive descent parser for grammar validation
'''

class Syntax_Analyzer:
    
    def parse(self, text, line = 0):
        self.tokens = lexical_analysis(text)
        self.current_token = None
        self.next_token = None
        self.char_num = 0
        self.line = line
        self.fail = False
        self.advance()
        self.expr()

        if self.fail == True:
            return None

        return [x for x in lexical_analysis(text)]

    def advance(self):
        self.current_token, self.next_token = self.next_token, next(self.tokens, None)

        if self.current_token != None:
            self.char_num += len(self.current_token.value)

    def accept(self, token_type):
        if self.next_token and self.next_token.type == token_type:
            self.advance()
            return True
        else:   
            return False

    def expect(self, token_type):
        if not self.accept(token_type):
            print("Expected %s at line %d:%d" % (token_type, self.line, self.char_num))
            self.fail = True

    # Syntax functions set

    '''
        expr   ::= term   { (+|-) term   }
        term   ::= factor { (*|/) factor }
        factor ::= NUM | VAR | FUN | ( expr )
    '''

    def expr(self):
        self.term()
        while self.accept('ADD') or self.accept('SUB'):
            self.term()

    def term(self):
        self.factor()
        while self.accept('MUL') or self.accept('DIV'):
            self.factor()

    def factor(self):
        # Digit or LPAREN -> ( exp )
        if self.accept('NUM') or self.accept('VAR') or self.accept('FUN'):
            return
        elif self.accept('LPAREN'):
            self.expr()
            self.expect('RPAREN')
        else:
            print("Expected NUMBER or ( at line %d:%d" % (self.line, self.char_num))
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
            while len(stack) != 0 and stack[-1] != '(':
                out.append(stack.pop())
            stack.pop()
        else:
            # Token is digit or some other symbol (currentlly not supported)
            out.append(token)

    # Pop all tokens from stack to output
    while len(stack) != 0:
        out.append(stack.pop())
    return out

syn_anal = Syntax_Analyzer()
e = "4 + 2 * 2"
o = syn_anal.parse(e)
if o:
    rpn = infix_to_rpn(o)
    for t in rpn:
        print(t)

