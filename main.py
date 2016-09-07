import sys; 
sys.dont_write_bytecode = True

from parser import *

def get_file(name):
    try:
        f = open(name, "r")
    except:
        print("Cannot open file: %s" % name)
        exit(0)
    content = f.read().split('\n')
    content = [x for x in content if x]
    return content

def main():
    f = get_file("stuff/prog")

    parser = Parser()

    i = 0
    for line in f:
        val = parser.parse(line, i)
        if val != None:
            print("%s = %d" % (line, val))
        else:
            print("%s (failed to compile)" % line)
        i += 1



if __name__ == "__main__":
    main()

