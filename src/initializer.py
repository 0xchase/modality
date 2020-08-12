from termcolor import colored
import r2angrdbg

class Initializer():
    def initialize_entry(self):
        state = self.r2angr.project.factory.entry_state(args=self.r2angr.argv, stdin=self.r2angr.stdin)

        #state.options.add(self.angr.options.SYMBION_SYNC_CLE)
        #state.options.add(self.angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

        self.r2angr.simgr = self.r2angr.project.factory.simgr(state, save_unconstrained=True)

        try:
            self.r2angr.r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))
        except:
            self.r2angr.r2p.cmd("s " + hex(state.solver.eval(state.regs.eip)))

        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr at entry point", "yellow"))

    def initialize_blank(self):
        self.r2angr.project = self.r2angr.angr.Project(self.r2angr.binary)
        self.r2angr.fast_project = self.r2angr.angr.Project(self.r2angr.binary, auto_load_libs=False)
        addr = self.r2angr.r2p.cmd("s")
        state = self.r2angr.project.factory.blank_state(addr=int(addr, 16), args=self.r2angr.argv, stdin=self.r2angr.stdin)
        self.r2angr.simgr = self.r2angr.project.factory.simgr(state)
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr blank state at current address", "yellow"))

    def initialize_debugger(self):
        r2angrdbg.init(self.r2angr.r2p)

        state = self.r2angr.project.factory.entry_state(args=self.r2angr.argv, stdin=self.r2angr.stdin)
        state = r2angrdbg.StateManager().get_state()

        state._set_options({self.r2angr.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})

        self.r2angr.simgr = self.r2angr.project.factory.simgr(state, save_unconstrained=True)

        try:
            self.r2angr.r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))
        except:
            self.r2angr.r2p.cmd("s " + hex(state.solver.eval(state.regs.eip)))

        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr using debugger state", "yellow"))

        #state_creator.state_from_debugger_state(self.r2angr.r2p)
        #sm = state_creator.StateManager()
