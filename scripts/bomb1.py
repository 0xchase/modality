#!/usr/bin/python3

import angr
import claripy

def solve_flag_1():

    # shutdown some warning produced by this example
    #logging.getLogger('angr.engines.vex.irsb').setLevel(logging.ERROR)

    proj = angr.Project('challenges/bomb')


    start = 0x400ee0
    bomb_explode = 0x40143a
    end = 0x400ef7

    proj.hook(0x8048b32, angr.SIM_PROCEDURES['libc']['strcmp']())
    state = proj.factory.blank_state(addr=0x8048b20)
    arg = state.solver.BVS("input_string", 8 * 128)

    bind_addr = 0x804b680
    state.memory.store(bind_addr, arg)
    state.add_constraints(state.regs.edi == bind_addr)

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=end, avoid=bomb_explode)

    if simgr.found:
        found = simgr.found[0]
        flag = found.solver.eval(arg, cast_to=bytes)
        return flag[:flag.index(b'\x00')].decode() # remove everyting after \x00 because they won't be compared
    else:
        print("angr failed to find a path to the solution :(")

solve_flag_1()
