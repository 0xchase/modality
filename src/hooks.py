
#project.hook(0x8048d7b, angr.SIM_PROCEDURES["libc"]["strcmp"]())
#project.hook(0x8048d3b, angr.SIM_PROCEDURES["libc"]["strlen"]())

#state.inspect.b("call", hit_call)
#state.inspect.b("return", hit_return)

class Hooks():
    loops_visited = {}
    loop_entry_addrs = []
    loop_exit_addrs = []
    discard_deadended = False


    def function_hook(self, state):
        name = "function"
        for addr, func in self.functions:
            if int(addr, 16) == state.addr:
                name = func
        print(self.colored("Called " + name, "green"))

    def library_function_hook(self, state):
        name = "function"
        for addr, func in self.library_functions:
            if int(addr, 16) == state.addr:
                name = func
        print(self.colored("Called " + name, "green"))

    def setup_functions(self):
        for addr, func in self.functions:
            self.project.hook(int(addr, 16), self.function_hook)

        for addr, func in self.library_functions:
            self.project.hook(int(addr, 16), self.library_function_hook)

    def print_disass_data(self, s, state):
        if "rbp" in s:
            if "-" in s:
                sub = int(str(s.split("-")[1]).replace(" ", "").replace("]", ""), 16)
                return str(state.memory.load(state.regs.rbp - sub, 4))
            else:
                return str(state.memory.load(state.regs.rbp, 4))
        else:
            return s

    def loop_hook(self, state):
        simgr = self.simgr
        loops_visited = self.loops_visited
        count = loops_visited[state.addr]
        block = self.project.factory.block(state.addr)
        if self.discard_deadended:
            simgr.deadended = []
        #block.pp()

        cmp_m = block.capstone.insns[0].mnemonic
        cmp_op = block.capstone.insns[0].op_str.split(",")

        cmp_str = ""
        if "cmp" in cmp_m:
            cmp_str = "[cmp " + self.print_disass_data(cmp_op[0], state) + ", " + self.print_disass_data(cmp_op[1], state) + "]"
        if count == 0:
            print(self.colored("Starting loop at " + hex(state.addr), "yellow"))
        else:
            print(self.colored(" [" + str(len(simgr.active)) + "|" + self.colored(str(len(simgr.deadended)), "red") + self.colored("]", "yellow"), "yellow"), self.colored("{Loop count: " + str(loops_visited[state.addr]) + "}", "cyan"), " Looping at " + hex(state.addr) + " " + cmp_str)
        loops_visited[state.addr] += 1

    def setup_loops(self, angr, project, simgr, filename,colored):
        self.colored = colored
        self.simgr = simgr
        self.project = project

        temp_project = angr.Project(filename, auto_load_libs=False)
        #return
        cfg_fast = temp_project.analyses.CFGFast()
        self.fast_project = temp_project

        addrs = []
        for f in cfg_fast.functions:
            addrs.append(f)

        functions = []
        for a in addrs:
            functions.append(cfg_fast.functions[a])

        loops = temp_project.analyses.LoopFinder(functions=functions).loops

        print("Found " + str(len(loops)) + " loops")

        for loop in loops:
            project.hook(loop.entry.addr, self.loop_hook)
            self.loops_visited[loop.entry.addr] = 0
            self.loop_entry_addrs.append(loop.entry.addr)

