import r2pipe
from tabulate import *

class Disassembler():
    def __init__(self, filename):
        r = r2pipe.open(filename)
        r.cmd("aa")

        temp_addrs = r.cmd("afll~[0]").split("\n")
        temp_names = r.cmd("afll~[14]").split("\n")
        
        self.functions = []

        for i in range(0, len(temp_addrs)):
            if "xref" not in temp_names[i] and temp_addrs[i] != "" and "imp" not in temp_names[i]:
                self.functions.append((hex(int(temp_addrs[i], 16)), temp_names[i]))

        self.library_functions = []

        for i in range(0, len(temp_addrs)):
            if "xref" not in temp_names[i] and temp_addrs[i] != "" and "imp" in temp_names[i]:
                self.library_functions.append((hex(int(temp_addrs[i], 16)), temp_names[i]))

        self.r = r

    def disassemble(self):
        command = self.command
        simgr = self.simgr
        r = self.r
        output = []
        num = 10
        if len(command) > 1:
            num = int(command[1])
        for s in simgr.active:
            output.append(r.cmd("pi " + str(num) + " @ " + hex(s.addr)))
        print(tabulate([output]))

        
