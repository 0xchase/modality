#!/usr/bin/python3

import sys
#sys.argv = ["temp", "../crackmes_one/Crackme-4"]
sys.argv = ["temp", "../crackmes_one/keygenme"]
from tool import *

#state = project.factory.blank_state(addr=0x40151c, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
state = project.factory.blank_state(addr=0x401169)
simgr = project.factory.simgr(state)

password = claripy.BVS("password", 16*8)
state.memory.store(state.regs.ebp - 0x8, password)

class hook_pow(angr.SimProcedure):
    def run(self, long1, long2):
        print("Hooked power function, args: " + str(long1) + " " + str(long2))
        return claripy.BVV(claripy.pow(long1, long2))

project.hook_symbol("pow", hook_pow())

#project.hook(0x401540, hook_new())

#print("Exploring now")
#simgr.explore(find=0x401528).unstash(from_stash="found", to_stash="active")

initialize(project, state, simgr)
command_line()
