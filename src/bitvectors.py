from termcolor import colored
import claripy

# Chage commands to kill/revive state by numbers rather than addresses

# ========== Commands ========== #
class Bitvectors():
    symbolic_values = []

    def symbolize_register(self):
        reg = self.r2angr.command[1]

        bvs32 = claripy.BVS("symbolic_value" + str(len(self.symbolic_values)), 32)
        bvs64 = claripy.BVS("symbolic_value" + str(len(self.symbolic_values)), 64)

        i = 0
        for state in self.r2angr.simgr.active:

            if reg == "eax":
                state.regs.eax = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "ebx":
                state.regs.ebx = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "ecx":
                state.regs.ecx = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "edx":
                state.regs.edx = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "esi":
                state.regs.esi = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "edi":
                state.regs.edi = bvs32
                self.symbolic_values.append(bvs32)
            elif reg == "rax":
                state.regs.rax = bvs64
                self.symbolic_values.append(bvs64)
            elif reg == "rbx":
                state.regs.rbx = bvs64
                self.symbolic_values.append(bvs64)
            elif reg == "rcx":
                state.regs.rcx = bvs64
                self.symbolic_values.append(bvs64)
            elif reg == "rdx":
                state.regs.rdx = bvs64
                self.symbolic_values.append(bvs64)
            elif reg == "rsi":
                state.regs.rsi = bvs64
                self.symbolic_values.append(bvs64)
            elif reg == "rdi":
                state.regs.rdi = bvs64
                self.symbolic_values.append(bvs64)
            else:
                print(colored("Register not supported", "red"))
                return

            print("Symbolizing " + reg + colored(" in active", "cyan") + " state " + str(i) + " at " + colored(hex(state.addr), "green"))

            i += 1

    def solve(self):
        print("Solving...")
        for state in self.r2angr.simgr.active:
            for value in self.symbolic_values:
                solution = state.solver.eval(value)
                print(solution)

