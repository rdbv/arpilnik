#!/usr/bin/python3
import os

while True:
    fifo = open("in0.fifo", "r")
    for line in fifo:
        if line == 'q\n':
            exit()
        else:
            os.system(line)
    fifo.close()
