#!/usr/bin/python3

import angr
import claripy

password = claripy.BVS('password', 8*0x20)

class hook_fgets(angr.SimProcedure):
    def run(self, dst, size, file_ptr):
        print("Hooked fgets() with arguments: " + str(dst) + " " + str(size) + " " + str(file_ptr))
        size = self.state.solver.eval(size)
        self.state.memory.store(dst, password)
        return dst

class hook_malloc(angr.SimProcedure):
    def run(self, sim_size):
        print("Hooked malloc() with argument: " + str(sim_size))
        print("Overriding malloc size with 0x51")
        return self.state.heap._malloc(claripy.BVV(0x51, 32))

class hook_strlen(angr.SimProcedure):
    def run(self, buf):
        print("Hooked strlen() with argument: " + str(buf))
        return 0xa + 1

project = angr.Project("challenges/hashmenot")
state = project.factory.entry_state()
simgr = project.factory.simgr(state)

project.hook_symbol("fgets", hook_fgets())
#project.hook(0x400993, hook_malloc())

@project.hook(0x400987, length=0)
def temp(state):
    print("Simulating move to eax")
    state.regs.eax = claripy.BVV(0x50, 32)

simgr.explore(find=0x4008d6).unstash(from_stash="found", to_stash="active")
print("At main function with " + str(len(simgr.active)) + " solutions")

simgr.explore(find=0x400970, avoid=[0x400928, 0x40095c]).unstash(from_stash="found", to_stash="active")
print("Past strlen with " + str(len(simgr.active)) + " solutions")

simgr.explore(find=0x4009e9, avoid=[0x4009a3]).unstash(from_stash="found", to_stash="active")
print("Past malloc with " + str(len(simgr.active)) + " solutions")

simgr.step()

for i in range(0, 1):
    simgr.explore(find=0x400b34, avoid=[]).unstash(from_stash="found", to_stash="active")
    print("Loop with " + str(len(simgr.active)) + " solutions")

simgr.explore(find=0x400a2b, avoid=[0x400a06])
if simgr.found:
    print("Found solution")
else:
    print("No solution found")
