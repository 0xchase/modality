from termcolor import colored

#project.hook(0x8048d7b, angr.SIM_PROCEDURES["libc"]["strcmp"]())
#project.hook(0x8048d3b, angr.SIM_PROCEDURES["libc"]["strlen"]())

#state.inspect.b("call", hit_call)
#state.inspect.b("return", hit_return)

class Hooks():
    def print_analysis(self, s):
        print(colored("[", "yellow") + colored("Hook", "yellow") + colored("] ", "yellow") + s)

    def aaa(self):
        print("Function call, loops, and memory r/w analysis")

        #for state in self.simgr.active:
        #    print("Adding read hooks to state")
        #    state.inspect.b("mem_read", when=self.angr.BP_AFTER, action=self.hook_read)
        for state in self.simgr.active:
            print("Adding split hooks to state")
            state.inspect.b("fork", when=self.angr.BP_AFTER, action=self.hook_fork)
            #state.inspect.b("return", when=self.angr.BP_AFTER, action=self.hook_return)

        #for state in self.simgr.active:
        #    print("Adding exit hooks to state")
        #    state.inspect.b("exit", when=self.angr.BP_AFTER, action=self.hook_exit)


    def hook_functions(self):
        for func in self.r2angr.r2p.cmdj("aflj"):
            if ".imp." in func["name"]:
                self.print_analysis("Hooking import: " + colored(func["name"], "green") + " at " + hex(func["offset"]))
                self.r2angr.project.hook(func["offset"], self.library_function_hook)
            else:
                self.print_analysis("Hooking function: " + colored(func["name"], "green") + " at " + hex(func["offset"]))
                self.r2angr.project.hook(func["offset"], self.function_hook)

    def function_hook(self, state):
        name = "function"
        for func in self.r2angr.r2p.cmdj("aflj"):
            if func["offset"] == state.addr:
                name = func["name"]
        self.print_analysis(colored("Called " + name, "green"))

    def library_function_hook(self, state):
        name = "function"
        for func in self.r2angr.r2p.cmdj("aflj"):
            if func["offset"] == state.addr:
                name = func["name"]
        self.print_analysis(colored("Called " + name, "green"))

    def print_disass_data(self, s, state):
        if "rbp" in s:
            if "-" in s:
                sub = int(str(s.split("-")[1]).replace(" ", "").replace("]", ""), 16)
                return str(state.memory.load(state.regs.rbp - sub, 4))
            else:
                return str(state.memory.load(state.regs.rbp, 4))
        else:
            return s

    loops_visited = {}
    loop_entry_addrs = []
    loop_exit_addrs = []

    def loop_hook(self, state):
        simgr = self.r2angr.simgr
        loops_visited = self.loops_visited
        count = loops_visited[state.addr]
        block = self.r2angr.project.factory.block(state.addr)
        #block.pp()

        cmp_m = block.capstone.insns[0].mnemonic
        cmp_op = block.capstone.insns[0].op_str.split(",")

        cmp_str = ""
        if "cmp" in cmp_m:
            cmp_str = "[cmp " + self.print_disass_data(cmp_op[0], state) + ", " + self.print_disass_data(cmp_op[1], state) + "]"
        if count == 0:
            print(colored("Starting loop at " + hex(state.addr), "yellow"))
        else:
            print(colored(" [" + str(len(simgr.active)) + "|" + colored(str(len(simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{Loop count: " + str(loops_visited[state.addr]) + "}", "cyan"), " Looping at " + hex(state.addr) + " " + cmp_str)
        loops_visited[state.addr] += 1

    def hook_loops(self):
        fast_project = self.r2angr.fast_project
        simgr = self.r2angr.simgr

        cfg_fast = fast_project.analyses.CFGFast()

        addrs = []
        for f in cfg_fast.functions:
            addrs.append(f)

        functions = []
        for a in addrs:
            functions.append(cfg_fast.functions[a])

        loops = fast_project.analyses.LoopFinder(functions=functions).loops

        print("Found " + str(len(loops)) + " loops")

        for loop in loops:
            self.r2angr.project.hook(loop.entry.addr, self.loop_hook)
            self.loops_visited[loop.entry.addr] = 0
            self.loop_entry_addrs.append(loop.entry.addr)


    def hook_read(self, state):
        print("Hooked READ at " + str(state.inspect.mem_read_expr) + " from " + str(state.inspect.mem_read_address))

    def hook_return(self, state):
        print(self.colored("Returned: " + str(state.regs.rax), "green"))

    def hook_fork(self, state):
        print(self.colored("Forked state at " + hex(state.addr), "yellow"))
        
    def hook_exit(self, state):
        print("State exited at " + hex(state.addr))

