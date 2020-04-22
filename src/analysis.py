
#project.hook(0x8048d7b, angr.SIM_PROCEDURES["libc"]["strcmp"]())
#project.hook(0x8048d3b, angr.SIM_PROCEDURES["libc"]["strlen"]())

#state.inspect.b("call", hit_call)
#state.inspect.b("return", hit_return)

class Analysis():
    
    def a(self):
        print("Function call analysis")

    def aa(self):
        print("Function call and loops analysis")

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

    def hook_read(self, state):
        print("Hooked READ at " + str(state.inspect.mem_read_expr) + " from " + str(state.inspect.mem_read_address))

    def hook_return(self, state):
        print(self.colored("Returned: " + str(state.regs.rax), "green"))

    def hook_fork(self, state):
        print(self.colored("Forked state at " + hex(state.addr), "yellow"))
        
    def hook_exit(self, state):
        print("State exited at " + hex(state.addr))

