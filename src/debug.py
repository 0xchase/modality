import sys
import claripy
from termcolor import colored
#import angr

class Debugger():
    def __init__(self, f):
        self.functions = f
        self.watchpoints = {}
    
    def initialize(self, main, f):
        global functions
        functions = f

    def debug_continue(self):
        self.simgr.run()

    def debug_step(self):
        if len(self.command) == 1:
            print("Single step")
            self.simgr.step()
        else:
            num = int(self.command[1])
            print("Multi step")
            for i in range(0, num):
                self.simgr.step()

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

    # CURRENTLY BROKEN
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

    def debug_print(self):
        print("[" + "-"*30 + "registers" + "-"*30 + "]")
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("RAX: " + str(self.simgr.active[0].regs.rax))
        print("[" + "-"*30 + "code" + "-"*30 + "]")
        print("some code here")
        print("[" + "-"*30 + "stack" + "-"*30 + "]")
        print("the stack here")
        print("[" + "-"*30 + "stack" + "-"*30 + "]")
        print("[" + "-"*30 + "    " + "-"*30 + "]")

    def debug_explore_until(self):
        print("Exploring until...")
        command = self.session.command
        simgr = self.session.simgr
        
        self.active_backup = simgr.active.copy()
        self.deadended_backup = simgr.deadended.copy()

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = int(self.symbol_to_address(command[1]), 16)

        print("Debug explore until " + hex(addr))
        simgr.explore(find=addr).unstash(from_stash="found", to_stash="active")

        if simgr.active:
            print(colored("Found " + str(len(simgr.active)) + " solutions", "green"))
        else:
            print(colored("Exploration failed, use der to restore", "red"))

        self.session.r2p.cmd("s " + hex(addr))

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

    def debug_registers(self):
        for state in self.simgr.active:
            print("State at " + str(state.regs.rip) + ":")
            if len(str(state.regs.rax)) < 50:
                print("  rax = " + str(state.regs.rax))
            else:
                print("  rax = <symbolic value>")
            if len(str(state.regs.rbx)) < 50:
                print("  rbx = " + str(state.regs.rbx))
            else:
                print("  rbx = <symbolic value>")
            if len(str(state.regs.rcx)) < 50:
                print("  rcx = " + str(state.regs.rcx))
            else:
                print("  rcx = <symbolic value>")
            if len(str(state.regs.rdx)) < 50:
                print("  rdx = " + str(state.regs.rdx))
            else:
                print("  rdx = <symbolic value>")
            if len(str(state.regs.rsi)) < 50:
                print("  rsi = " + str(state.regs.rsi))
            else:
                print("  rsi = <symbolic value>")
            if len(str(state.regs.rdi)) < 50:
                print("  rdi = " + str(state.regs.rdi))
            else:
                print("  rdi = <symbolic value>")
            if len(str(state.regs.rsp)) < 50:
                print("  rsp = " + str(state.regs.rsp))
            else:
                print("  rsp = <symbolic value>")
            if len(str(state.regs.rbp)) < 50:
                print("  rbp = " + str(state.regs.rbp))
            else:
                print("  rbp = <symbolic value>")


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
        print("Debug continue until " + self.command[1])
        #self.simgr.run(until=lambda sm: state.addr == int(self.command[1], 16) for state in sm.active) 
        print("Unimplemented")

    def debug_continue_output(self):
        print("Debug continue until output")
        output = self.simgr.active[0].posix.dumps(1)
        try:
            self.simgr.run(until=lambda sm: sm.active[0].posix.dumps(1) != output)
        except:
            print("Deadended")

        output = self.simgr.active[0].posix.dumps(1)
        try:
            print(output.decode())
        except:
            print(str(output))

    def debug_continue_until_call(self):
        print("Debug continue until self, main")
        state.inspect.b("call")
        #simgr.run(until=lambda sm: sm.active[0].addr == 0x400815)
        self.simgr.run()

    def debug_continue_until_branch(self):
        print("Continuing until branch")
        while len(self.session.simgr.active) == 1:
            self.session.simgr.step()
        

    def debug_continue_until_ret(self):
        print("Debug continue until ret")
        self.simgr.run()

    def debug_continue_until_call(self):
        print("Debug continue until call")
        self.simgr.run()


    def debug_initialize(self):
        command = self.command
        simgr = self.simgr
        if len(command) == 1:
            print("Initializing at entry state")
            state = self.project.factory.entry_state()
            simgr = self.project.factory.simgr(state)
        else:
            print("Initializing blank state at " + command[1])

            state = self.project.factory.blank_state(addr=int(command[1],16))
            simgr = self.project.factory.simgr(state)

    def symbol_to_address(self, s):
        for f in self.session.r2p.cmdj("aflj"):
            if f["name"] == s:
                return hex(f["offset"])

