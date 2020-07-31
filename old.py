import angr
import claripy
from termcolor import colored
from pwn import *

from src.concrete.target import R2ConcreteTarget

class hook_printf(angr.procedures.libc.printf.printf):

    def run(self):
        print("Hooked printf at " + hex(self.addr))
        #print(str(self._compute_ret_addr()))

        return super(type(self), self).run()

class hook_scanf(angr.procedures.libc.scanf.scanf):
    hit = False

    def run(self, fmt):
        hit = True
        print("Hooked scanf at " + hex(self.addr) + " with format string " + str(fmt))
        return super(type(self), self).run(fmt)

def fully_symbolic(state, variable):
    for i in range(state.arch.bits):
        if not state.solver.symbolic(variable[i]):
            print("Found non-symbolic bit")
            return False
    return True

def print_shellcode(shellcode):
    shellcode_str = ""
    for byte in shellcode:
        shellcode_str += "\\x" + hex(byte)[2:].zfill(2).replace("00", "41").replace("01", "41")

    final = ""
    for byte in shellcode_str.split("\\x"):
        if not byte == "":
            temp = "\\x" + byte
            if "41" in byte:
                temp = colored(temp, "blue")
            if "42" in byte:
                temp = colored(temp, "red")

            final += temp

    print(final)
        

def exploitFinder():
    #p = angr.Project("stack0", load_options={"auto_load_libs": False})

    p = angr.Project("basic", load_options={"auto_load_libs": False})

    hook = hook_scanf()

    #p.hook_symbol("printf", hook_printf())
    #p.hook_symbol("__isoc99_scanf", hook)

    stdin = claripy.BVS("stdin", 300*8)
    state = p.factory.entry_state(stdin=stdin);
    simgr = p.factory.simgr(state, save_unconstrained=True);

    while len(simgr.active) > 0:
        print(list(simgr.active[0].memory.addrs_for_name("stdin")))
        simgr.step()
    
    return

    go = True
    while len(simgr.active) > 0:
        #print(str(simgr) + " " + str(simgr.active[0].regs.rip))
        simgr.step()

        if len(simgr.unconstrained) > 0:
            print("Found unconstrained state")

            for s in simgr.unconstrained:
                if fully_symbolic(s, s.regs.pc):
                    print("Reached fully symbolic pc")
                    #break

                # Less zeratool
                state_copy = s.copy()
                constraints = []
                for i in range(int(state_copy.arch.bits/8)):
                    constraints.append(claripy.And(state_copy.regs.pc.get_byte(i) == 0x42))

                if state_copy.solver.satisfiable(extra_constraints=constraints):
                    print("Can constriant pc to 0x42424242")
                    for constraint in constraints:
                        state_copy.add_constraints(constraint)

                print("Vulnerable path found:\n")

                print(str(list(s.memory.addrs_for_name("stdin"))))

                stdin_shellcode = state_copy.posix.dumps(0)

                stdin_shellcode = stdin_shellcode[0:stdin_shellcode.rfind(b'\x42')+1]
                print_shellcode(stdin_shellcode)

                simgr.unconstrained.remove(s)



            simgr.drop(stash="unconstrained")

exploitFinder()

