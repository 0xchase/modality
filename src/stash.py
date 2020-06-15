from termcolor import colored
import claripy

# Chage commands to kill/revive state by numbers rather than addresses

# ========== Commands ========== #
class Stash():
    def info(self):
        i = 0
        for state in self.r2angr.simgr.active:
            self.print_return(colored("Active", "cyan") + " state " + str(i) + " at " + colored(hex(state.addr), "green"))
            s = self.r2angr.r2p.cmd("pdi 5 @ " + hex(state.addr))
            for line in s.split("\n"):
                self.print_return("   " + line)
            i += 1

    def list(self):
        table = []
        if len(self.r2angr.simgr.active) > 0:
            self.print_return(colored("Active", "cyan") + " states:")
            for i in range(0, len(self.r2angr.simgr.active)):
                self.print_return("  " + str(i) + " " + colored(hex(self.r2angr.simgr.active[i].addr), "yellow"))
            self.print_return("")

        if len(self.r2angr.simgr.deadended) > 0:
            self.print_return(colored("Deadended", "red") + " states:")
            for i in range(0, len(self.r2angr.simgr.deadended)):
                self.print_return("  " + str(i) + " " + colored(hex(self.r2angr.simgr.deadended[i].addr), "yellow"))
            self.print_return("")

    def print_input(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr
        print("Printing input")
        addr = 0

        if len(command) == 1:
            i = 0
            print("Made it here " + str(len(self.r2angr.simgr.active)))
            for state in self.r2angr.simgr.active:
                print(colored("Active", "cyan") + " state " + str(i) + " at " + colored(hex(state.addr), "green") + ":")
                try:
                    print(state.posix.dumps(0).decode())
                except:
                    print(state.posix.dumps(0))
                i += 1
        elif "0x" in command[1]:
            for state in simgr.active:
                if state.addr == addr:
                    self.print_decode(state.posix.dumps(0))
        else:
            self.print_decode(simgr.active[int(command[1])].posix.dumps(0))

    def print_output(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr
        addr = 0

        if len(command) == 1:
            i = 0
            for state in simgr.active:
                self.print_return(colored("Active", "cyan") + " state " + str(i) + " at " + colored(hex(state.addr), "green") + ":")
                self.print_decode(state.posix.dumps(1))
                i += 1
        elif "0x" in command[1]:
            for state in simgr.active:
                if state.addr == addr:
                    self.print_decode(state.posix.dumps(1))
        else:
            self.print_decode(simgr.active[int(command[1])].posix.dumps(1))

    def kill(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr
        addr = 0

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = simgr.active[int(command[1])].addr

        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == addr)

    def extract(self):
        simgr = self.r2angr.simgr
        command = self.r2angr.command
        addr = 0

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = simgr.active[int(command[1])].addr
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr != addr)

    def seek(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr
        if "0x" in command[1]:
            addr = int(command[1], 16)
            simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr != addr)
            self.r2angr.r2p.cmd("s " + command[1])
        else:
            num = int(command[1])
            temp = simgr.active[num]
            self.r2angr.r2p.cmd("s " + hex(temp.addr))

    def revive(self):
        command = self.r2angr.command
        simgr = self.r2angr.simgr
        addr = 0

        if "0x" in command[1]:
            addr = int(command[1], 16)
        else:
            addr = simgr.deadended[int(command[1])].addr

        simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: s.addr == addr)

    def revive_all(self):
        simgr = self.r2angr.simgr
        simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: True)

    def revive_stdout(main, command, simgr):
        if len(command) > 1:
            i = 0
            while i < len(simgr.deadended):
                state = simgr.deadended[i]
                if command[1].encode() in state.posix.dumps(1):
                    simgr.active.append(state)
                    simgr.deadended.remove(state)
                    i -= 1
                i += 1

    def kill_stdout(main, command, simgr):
        if len(command) > 1:
            i = 0
            while i < len(simgr.active):
                state = simgr.active[i]
                if command[1].encode() in state.posix.dumps(1):
                    simgr.deadended.append(state)
                    simgr.active.remove(state)
                    i -= 1
                i += 1

    def kill_all(self):
        simgr = self.r2angr.simgr
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: True)

    # ========== Utilities ========== #

    def get_name(state):
        if hasattr(state, "name"):
            return state.name
        else:
            return hex(state.addr)

    def print_decode(self, data):
        try:
            self.print_return(data.decode())
        except:
            self.print_return(str(data))

    def print_return(self, s):
        self.r2angr.return_value += s + "\n"
