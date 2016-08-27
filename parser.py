import re

LEFT_ASSOC  = 0
RIGHT_ASSOC = 1

operators = {
    '+' : (0, LEFT_ASSOC),
    '-' : (0, LEFT_ASSOC),
    '*' : (1, LEFT_ASSOC),
    '/' : (1, LEFT_ASSOC),
}

def split_expression(exp):
    splitted = re.split("([(+-/*=)])", exp.replace(" ", ""))
    splitted = [x for x in splitted if x]
    return splitted

def is_operator(token):
    return token in operators 

def is_assoc(token, assoc):
    if not is_operator(token):
        raise ValueError('Invalid token: %s' % token)
    return operators[token][1] == assoc

def cmp_prec(token1, token2):
    if not is_operator(token1) or not is_operator(token2):
        raise ValueError('Invalid tokens: %s %s' % (token1, token2))
    return operators[token1][0] - operators[token2][0]

def infix_to_rpn(infix_exp):
    out = []
    stack = []
    for token in split_expression(infix_exp):
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
        elif token == '(':
            # If token is ( then, just append to stack
            stack.append(token)
        elif token == ')':
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

def compute_rpn_val(rpn_exp):
    stack = []
    for token in rpn_exp:
        if token.isdigit():
            stack.append(token)
        else:
            a = float(stack.pop())
            b = float(stack.pop())
            if token == '-':    stack.append(b-a)
            if token == '+':    stack.append(b+a)
            if token == '*':    stack.append(b*a)
            if token == '/':    stack.append(b/a)
    if len(stack) != 1:
        raise RuntimeError("Uh oh! (Invalid RPN expression) (%s)" % rpn_exp)
    return stack

def valid_infix_exp(infix_exp):
    splitted = split_expression(infix_exp)
    print(splitted)
    if splitted.count('(') != splitted.count(')'):
        print("[Syntax]: '(' count is not equal to ')' count")
        return 0
    return 1

def is_valid_varname(name):
    return re.match("[_A-Za-z][_a-zA-Z0-9]*$",name)

