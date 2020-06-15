from termcolor import colored

class Initializer():
    def initialize_entry(self):
        self.r2angr.project = self.r2angr.angr.Project(self.r2angr.binary)
        self.r2angr.fast_project = self.r2angr.angr.Project(self.r2angr.binary, auto_load_libs=False)
        state = self.r2angr.project.factory.entry_state(args=self.r2angr.argv, stdin=self.r2angr.stdin)
        self.r2angr.simgr = self.r2angr.project.factory.simgr(state)
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr at entry point", "yellow"))

    def initialize_blank(self):
        self.r2angr.project = self.r2angr.angr.Project(self.r2angr.binary)
        self.r2angr.fast_project = self.r2angr.angr.Project(self.r2angr.binary, auto_load_libs=False)
        addr = self.r2angr.r2p.cmd("s")
        state = self.r2angr.project.factory.blank_state(addr=int(addr, 16), args=self.r2angr.argv, stdin=self.r2angr.stdin)
        self.r2angr.simgr = self.r2angr.project.factory.simgr(state)
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr blank state at current address", "yellow"))
