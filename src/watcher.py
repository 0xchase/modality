from termcolor import colored

class Watcher():
    watchpoints = {}

    def hook_watchpoint(self, state):
        addr = state.solver.eval(state.regs.rip)
        hit_count, message = self.watchpoints[addr]
        self.watchpoints[addr] = (hit_count + 1, message)

        if message == "":
            data = colored(" [" + str(len(self.r2angr.simgr.active)) + "|" + colored(str(len(self.r2angr.simgr.deadended)), "red") + colored("]", "yellow"), "yellow") + " " + colored("{Hits: " + str(hit_count) + "}", "cyan") + " Hit watchpoint at " + hex(addr)
            print(data)
        else:
            data = colored(" [" + str(len(self.r2angr.simgr.active)) + "|" + colored(str(len(self.r2angr.simgr.deadended)), "red") + colored("]", "yellow"), "yellow") + " " + colored("{Hit count: " + str(hit_count) + "}", "cyan") + " " + message
            print(data)

    def add_watchpoint(self):
        addr = int(self.r2angr.command[1], 16)
        print("Adding watchpoint at " + hex(addr))
        self.r2angr.project.hook(addr, self.hook_watchpoint, length=0)

        if len(self.r2angr.command) >= 3:
            self.watchpoints[addr] = (0, " ".join(self.r2angr.command[2:]))
        else:
            self.watchpoints[addr] = (0, "")
