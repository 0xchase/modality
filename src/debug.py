import sys
import claripy
from termcolor import colored

class Debugger():
    watchpoints = {}

    def __init__(self):
        pass

    # Continues execution
    def debug_continue(self):
        self.print_debug("Continuing emulation")
        self.r2angr.simgr.run()

    # Steps execution 
    def debug_step(self):
        self.print_debug("Continuing emulation one step")

        if len(self.r2angr.command) == 1:
            self.r2angr.simgr.step()
        else:
            try:
                num = int(self.command[1])
            except:
                print("Usage: mcs <step count>")
                return

            for i in range(0, num):
                self.r2angr.simgr.step()

    def debug_function(self):
        print("Running function")
        f = self.project.factory.callable(int(self.command[1], 16))
        for i in range(2, len(self.command)):
            try:
                self.command[i] = int(self.command[i])
            except:
                try:
                    self.command[i] = int(self.command[i], 16)
                except:
                    pass
        if len(self.command[2:]) == 0:
            print(colored("Calling function with 0 arguments", "yellow"))
            f()
        elif len(self.command[2:]) == 1:
            print(colored("Calling function with 1 arguments", "yellow"))
            f(self.command[2])
        elif len(self.command[2:]) == 2:
            print(colored("Calling function with 2 arguments", "yellow"))
            f(self.command[2], self.command[3])
        elif len(self.command[2:]) == 3:
            print(colored("Calling function with 3 arguments", "yellow"))
            f(self.command[2], self.command[3], self.command[4])
        else:
            print(colored("Unsupported number of arguments", "red"))
            return
        print("")
        print(colored("Return value: " + str(f.result_state.regs.rax), "yellow"))
        print(colored("Return concrete: " + str(f.result_state.regs.rax.concrete), "green"))


    def restore_state(self, simgr1):
        simgr1.active = self.active_backup
        simgr1.deadended = self.deadended_backup

    # Explores using find/avoid addresses
    def debug_explore(self):
        r2p = self.r2angr.r2p
        find = []
        avoid = []

        comments = r2p.cmdj("CCj")
        for comment in comments:
            if comment["name"] == "find":
                find.append(comment["offset"])
            if comment["name"] == "avoid":
                avoid.append(comment["offset"])

        if len(find) == 0:
            print(colored("Requires at least one find comment", "yellow"))
            return

        f_str = ""
        for a in find:
            f_str += colored(hex(a), "green") + colored(", ", "yellow")
        f_str = f_str[:-6]

        a_str = ""
        for a in avoid:
            a_str += colored(hex(a), "red") + colored(", ", "yellow")
        a_str = a_str[:-6]

        self.print_debug(colored("Starting exploration.\nFind: [", "yellow") + f_str + colored("]. Avoid: [", "yellow") + a_str + colored("].", "yellow"))

        self.r2angr.simgr.explore(find=find, avoid=avoid)


        if self.r2angr.simgr.active:
            self.print_explore()
            self.r2angr.simgr.unstash(from_stash="found", to_stash="active")
        else:
            print(colored("Exploration failed", "red"))

    def debug_explore_stdout(self):
        print("Exploring until stdout " + self.command[1])
        self.simgr.explore(find=lambda s: self.command[1].strip().encode() in s.posix.dumps(1)).unstash(from_stash="found", to_stash="active")

    def debug_explore_until_dfs(self):
        print("Exploring using DFS")
        command = self.command
        simgr = self.simgr
        simgr.use_technique(self.angr.exploration_techniques.dfs.DFS())

        old_active = []
        old_deadended = []

        for state in simgr.active:
            old_active.append(state)

        for state in simgr.deadended:
            old_deadended.append(state)

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = int(self.symbol_to_address(command[1]), 16)

        simgr.use_technique(self.angr.exploration_techniques.explorer.Explorer())

        print("Debug explore until " + hex(addr))
        old_state = state
        simgr.explore(find=addr).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print(colored("Found " + str(len(simgr.active)) + " solutions", "green"))
        else:
            print(colored("Exploration failed", "red"))

            print("Reverting state (currently a bit buggy)")

            simgr.active = []
            simgr.deadended = []

            for state in old_active:
                simgr.active.append(state)
            for state in old_deadended:
                simgr.deadended.append(state)

    # Explore until a certain address
    def debug_explore_until(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr


        try:
            addr = self.get_addr(command[1])
        except:
            print(colored(str(command[1]) + " not found", "yellow"))
            return

        self.print_debug(colored("Starting exploration. Find: [", "yellow") + colored(hex(addr), "green") + colored("]", "yellow"))

        simgr.explore(find=addr)

        if simgr.found:
            self.print_explore()
            simgr.unstash(from_stash="found", to_stash="active")
        else:
            print(colored("Exploration failed, use der to restore", "red"))


    def debug_explore_revert(self):
        print("Restoring state")
        self.simgr.active = self.active_backup
        self.simgr.deadended_backup = self.deadended_backup

    def debug_explore_until_loop(self):
        command = self.command
        simgr = self.simgr

        self.save_state(simgr)
        temp_project = self.angr.Project(self.filename, auto_load_libs=False)

        print("Debug explore until loop")
        simgr.explore(find=self.loop_entry_addrs).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print(colored("Found " + str(len(simgr.active)) + " solutions", "green"))
        else:
            print(colored("Exploration failed", "red"))

    def loop_hook(self, state):
        loop = state.loop_data.current_loop
        #analysis = self.project.analyses.LoopAnalysis(loop, None)
        #print(str(analysis))
        #print(str(state.loop_data.header_trip_counts))
        sys.stdout.write("\b")
        sys.stdout.write("=>")
        sys.stdout.flush()

    def debug_explore_loop(self):
        command = self.command
        simgr = self.simgr

        old_active = []
        old_deadended = []

        for state in simgr.active:
            old_active.append(state)

        for state in simgr.deadended:
            old_deadended.append(state)

        temp_project = self.angr.Project(self.filename, auto_load_libs=False)

        cfg_fast = temp_project.analyses.CFGFast()
        addrs = []
        for f in cfg_fast.functions:
            addrs.append(f)
        functions = []
        for a in addrs:
            functions.append(cfg_fast.functions[a])

        loops = temp_project.analyses.LoopFinder(functions=functions).loops

        simgr.use_technique(self.angr.exploration_techniques.loop_seer.LoopSeer(cfg=cfg_fast, functions=functions, loops=loops, use_header=False, bound=None, bound_reached=None, discard_stash='deadended'))
        #analysis = temp_project.analyses.LoopAnalysis(loop_finder.loops[0], None)
        #print(str(analysis))
        self.project.hook(0x4008f4, self.loop_hook, length=0)

        print("Starting loop")
        sys.stdout.write(" [=")
        sys.stdout.flush()

        simgr.explore(find=0x4008fa).unstash(from_stash="found", to_stash="active")
        print("]")

        simgr.use_technique(self.angr.exploration_techniques.explorer.Explorer())

        exit()

        print("Debug explore until loop")
        old_state = state
        simgr.explore(find=entries).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print(colored("Found " + str(len(simgr.active)) + " solutions", "green"))
        else:
            print(colored("Exploration failed", "red"))

            print("Reverting state (currently a bit buggy)")

            simgr.active = []
            simgr.deadended = []

            for state in old_active:
                simgr.active.append(state)
            for state in old_deadended:
                simgr.deadended.append(state)

    def hook_watchpoint(self, state):
        addr = state.solver.eval(state.regs.rip)
        hit_count, message = self.watchpoints[addr]
        self.watchpoints[addr] = (hit_count + 1, message)

        if message == "":
            data = colored(" [" + str(len(self.simgr.active)) + "|" + colored(str(len(self.simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{Hit count: " + str(hit_count) + "}", "cyan"), " Reached watchpoint at " + hex(addr)
            state.history_arr.append(data)
            print(data)
        else:
            data = colored(" [" + str(len(self.simgr.active)) + "|" + colored(str(len(self.simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{Hit count: " + str(hit_count) + "}", "cyan"), " " + message
            state.history_arr.append(data)
            print(data)

    def debug_watch(self):
        addr = int(self.command[1], 16)
        print("Adding watchpoint at " + hex(addr))
        self.project.hook(addr, self.hook_watchpoint, length=0)

        if len(self.command) >= 3:
            self.watchpoints[addr] = (0, " ".join(self.command[2:]))
        else:
            self.watchpoints[addr] = (0, "")

    def hook_mergepoint(self, state):
        addr = state.solver.eval(state.regs.rip)
        simgr = self.simgr
        merge_count = 0

        i = 0
        j = len(simgr.active)
        while len(simgr.active) > 1 and i < 30:
            s_merged, flag, anything_merged = simgr.active[0].merge(simgr.active[1])
            i += 1
            if anything_merged:
                merge_count += 1
                simgr.active.remove(simgr.active[0])
                simgr.active[0] = s_merged
            else:
                print("Merge failed")
        print(colored(" [" + str(len(self.simgr.active)) + "|" + colored(str(len(self.simgr.deadended)), "red") + colored("]", "yellow"), "yellow"), colored("{Merging " + str(merge_count) + " states}", "cyan"), " Merging states at " + hex(addr))

    def debug_merge(self):
        addr = int(self.command[1], 16)
        print("Adding mergepoint at " + hex(addr))
        self.project.hook(addr, self.hook_mergepoint, length=0)

    def find(self, state):
        return self.find_string in state.posix.dumps(1)

    def avoid(self, state):
        return self.avoid_string in state.posix.dumps(1)

    def debug_explore_until_stdout(self):
        command = self.command
        simgr = self.simgr
        self.find_string = command[1].encode()
        self.avoid_string = command[2].encode()
        simgr.explore(find=self.find, avoid=self.avoid)

        if simgr.active:
            print("Found " + str(len(simgr.active)) + " solutions")
        else:
            print("Exploration failed")



    def debug_continue_until(self):
        simgr = self.r2angr.simgr

        try:
            addr = get_addr(self.r2angr.command[1])
            print(str(addr))
        except:
            print(colored("Usage: mcu <address|symbol>", "yellow"))
            return

        self.print_debug("Continuing until " + hex(addr))

        while len(simgr.active) > 0 and simgr.active[0].addr != addr:
            simgr.step()

    # Continue emulation until new data in stdout
    def debug_continue_output(self):
        self.print_debug("Debug continue until output")
        output = self.r2angr.simgr.active[0].posix.dumps(1)
        output = []

        for state in self.r2angr.simgr.active:
            output.append(state.posix.dumps(1))
        
        stdout = ""
        cont = True
        while cont:
            self.r2angr.simgr.step()
            for i in range(0, len(output)):
                if output[i] != self.r2angr.simgr.active[i].posix.dumps(1):
                    cont = False
                    stdout = self.r2angr.simgr.active[i].posix.dumps(1)

        try:
            print(stdout.decode())
        except:
            print(str(stdout))

    # Continue emulation until a branch
    def debug_continue_until_branch(self):
        print("Continuing until branch")

        current = len(self.r2angr.simgr.active)
        while len(self.r2angr.simgr.active) <= current and len(self.r2angr.simgr.active) > 0:
            self.r2angr.simgr.step()


    def debug_continue_until_ret(self):
        print("Debug continue until ret")
        self.simgr.run()

    def debug_continue_until_call(self):
        print("Debug continue until call")
        self.simgr.run()

    def get_addr(self, s):
        if self.r2angr.r2p.cmd("afl") != "":
            functions = self.r2angr.r2p.cmdj("aflj")
        else:
            functions = None

        if functions != None:
            for f in functions:
                if f["name"] == s:
                    return f["offset"]

        if "0x" in str(s):
            return int(s, 16)
        else:
            return int(s)

    def print_explore(self):
        self.print_debug(colored("Found " + str(len(self.r2angr.simgr.found)) + " solutions", "green"))
    
    def print_debug(self, s):
        print(colored("[", "yellow") + colored("DEBUG", "blue") + colored("] ", "yellow") + colored(s, "yellow"))
