import claripy

class Printer():
    def __init__(self):
        pass

    def args(self):
        for s in self.simgr.active:
            for i in range(1, len(self.argv1)):
                print(str(self.argv1[i]) + ": ", end='')
                result = s.solver.eval(self.argv1[i], cast_to=bytes)
                self.print_decode(result)

    def args_all(self):
        for s in self.simgr.active + self.simgr.deadended:
            for i in range(1, len(self.argv1)):
                result = s.solver.eval(self.argv1[i], cast_to=bytes)
                self.print_decode(result)

    def stdout(self):
        if len(self.command) == 1:
            for state in self.simgr.active:
                self.print_decode(state.posix.dumps(1))

    def stdin(self):
        if len(self.command) == 1:
            for state in self.simgr.active:
                self.print_decode(state.posix.dumps(0))
        else:
            self.print_decode(self.simgr.active[int(command[1])].posix.dumps(0))

    def stdout_all(self):
        if len(self.command) == 1:
            for state in self.simgr.active + self.simgr.deadended:
                self.print_decode(state.posix.dumps(1))

    def stdin_all(self):
        if len(self.command) == 1:
            for state in self.simgr.active + self.simgr.deadended:
                self.print_decode(state.posix.dumps(0))
        else:
            self.print_decode(self.simgr.active[int(command[1])].posix.dumps(0))

    def states(self):
        i = 0
        for state in self.simgr.active:
            print("State " + str(i) + " @ " + hex(state.addr))
            i += 1

    # Currently broken
    def states_history(self):
        i = 0
        for state in self.simgr.active:
            print("State " + str(i) + " @ " + hex(state.addr))
            try:
                for s in state.history_arr:
                    print(s)
            except:
                print("Couldn't find history")
            i += 1

    def states_constraints(self):
        i = 0
        for state in self.simgr.active:
            print("State " + str(i) + " @ " + hex(state.addr))
            #print("\t Basic Block Addrs: " + str(" ".join(str(state.history.bbl_addrs))))
            #print("\t Jump kinds: " + str(" ".join(str(state.history.jumpkinds))))
            guards = state.history.jump_guards
            output = ""
            for g in guards:
                if "Bool True" not in str(g):
                    output += "\t" + str(g) + "\n"
            print("Constraints: \n" + output)
            i += 1

    def states_path(self):
        i = 0
        for state in self.simgr.active:
            print("State " + str(i) + " @ " + hex(state.addr))
            #print("\t Descriptions: " + str(" ".join(state.history.descriptions)))
            #print("\t Basic Block Addrs: " + str(" ".join(str(state.history.bbl_addrs))))
            #print("\t Jump kinds: " + str(" ".join(str(state.history.jumpkinds))))
            guards = state.history.descriptions
            output = ""
            for g in guards:
                output += "\t" + str(g) + "\n"
            print("Path: \n" + output)
            i += 1

    def states_events(self):
        i = 0
        for state in self.simgr.active:
            data = state.history.events
            output = ""
            for g in data:
                if "Bool True" not in str(g):
                    output += "\t" + str(g) + "\n"
            print("Events:\n" + output)

            i += 1

    def states_tree(self):
        i = 0
        for state in self.simgr.active:
            print("State " + str(i) + " @ " + hex(state.addr))
            i += 1

    def print_decode(self, s):
        try:
            print(s.decode())
        except:
            print(str(s))
