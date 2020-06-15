#!/usr/bin/python3

from debug import *
from stash import *
from disass import *
from printer import *
from hooks import *
from util import *
from watcher import *
from initializer import *
from bitvectors import *

from threading import Thread
from time import sleep

# Add command to access old mounting commands
# Add all old commands. Go through each, making sure it works. Make commands robust.
# Add load commands (load registers, stack, etc) from debug session
# Add symbolize commands stdin, register, arg, etc
# Create visual mode for angr data???
# Add commands to seek between states: mss <index> (seek to index), mss+ (seek to next state) mss- (seek to previous state)
# Can declare an exploration sequence (find1, find2, find3, find4, etc). Use mes to explore this list of comments.
# Add keys to visual mode to seek between symbolic states
# Continue commands seek to addresses during emulation
# Use lambdas to add state comments/highlights to in radare2 during exploration
# Command to quit exploration
# Command to quit continuation

# Commands to add/remove find/avoid. Commands to remove all. Commands to list find/avoid.
# Get rid of classes, import all of them into sessions class
# Find/avoid commands (add comments at address). Work with @.
# Make find/avoid commands recolor block (can disable this in config).
# Make debugger comment/recolor/highlight at state location

class R2ANGR():
    is_initialized = False
    stdin = ""
    argv = []
    command = ""

    debugger = Debugger()
    stash = Stash()
    watcher = Watcher()
    hooks = Hooks()
    initializer = Initializer()
    bitvectors = Bitvectors()

    return_value = ""

    commands = [
            ("c", debugger.debug_continue,                  "c" + colored("[?]                 ", "yellow") + colored("Continue emulation", "green")),
            ("e", debugger.debug_explore,                  "e" + colored("[?]                 ", "yellow") + colored("Explore using find/avoid comments", "green")),
            ("i", None,                                     "i" + colored("[?]                 ", "yellow") + colored("Initialize at entry point", "green")),
            ("ie", initializer.initialize_entry,                                     "ie" + colored("[?]                 ", "yellow") + colored("Initialize at entry point", "green")),
            ("ib", initializer.initialize_blank,                                     "ib" + colored("[?]                 ", "yellow") + colored("Initialize blank state at current address", "green")),
            ("s", stash.list,                  "s" + colored("[?]                 ", "yellow") + colored("States list", "green")),

            ("h", None,                  "h" + colored("[?]                 ", "yellow") + colored("Hooks", "green")),
            ("hf", hooks.hook_functions,                  "hf" + colored("                    ", "yellow") + colored("Hook all functions", "green")),
            ("hl", hooks.hook_loops,                  "hl" + colored("                    ", "yellow") + colored("Hook all loops", "green")),

            ("cs", debugger.debug_step,           "cs" + colored(" <addr>            ", "yellow") + colored("Continue emulation one step", "green")),
            ("cu", debugger.debug_continue_until,           "cu" + colored(" <addr>            ", "yellow") + colored("Continue emulation until address", "green")),
            ("cb", debugger.debug_continue_until_branch,    "cb                   " + colored("Continue emulation until branch", "green")),
            ("co", debugger.debug_continue_output,          "co                   " + colored("Continue emulation until output", "green")),

            ("eu", debugger.debug_explore_until,            "eu" + colored(" <addr>            ", "yellow") + colored("Explore until address", "green")),
            ("eo", debugger.debug_explore_output,            "eo" + colored(" <string>          ", "yellow") + colored("Explore until string is in stdout", "green")),

            ("sl", stash.list,                              "sl"+colored(" <index>           ", "yellow") + colored("List states", "green")),
            ("slv", stash.info,                              "slv"+colored("                  ", "yellow") + colored("List active state verbose", "green")),
            ("si", stash.print_input,                              "si"+colored("                   ", "yellow") + colored("Print state stdin", "green")),
            ("so", stash.print_output,                              "so"+colored("                   ", "yellow") + colored("Print state stdout", "green")),
            ("sk", stash.kill,                  "sk" + colored("[?] <index|addr>   ", "yellow") + colored("Kill state by index or address", "green")),
            ("ska", stash.kill_all,                              "ska"+colored("                  ", "yellow") + colored("Kill all states", "green")),
            ("sr", stash.revive,                  "sr" + colored("[?] <index|addr>   ", "yellow") + colored("Revive state by index or address", "green")),
            ("sra", stash.revive_all,                              "sra"+colored("                  ", "yellow") + colored("Revive all states", "green")),
            ("ss", None,                  "ss" + colored("[?] <index|addr>   ", "yellow") + colored("", "green")),
            ("br", bitvectors.symbolize_register,                  "br" + colored("                    ", "yellow") + colored("Symbolize register with a bitvector", "green")),
            ("bs", bitvectors.solve,                  "bs" + colored("                    ", "yellow") + colored("Solve all bitvector values", "green")),
            ("se", stash.extract,                              "se"+colored(" <index|addr>      ", "yellow") + colored("Extract single state and kill all others", "green")),

            ("w", watcher.add_watchpoint,                              "w"+colored("[?] <addr>          ", "yellow") + colored("Add a watchpoint", "green")),
            ("wl", watcher.list_watchpoints,                              "wl"+colored("                   ", "yellow") + colored("List watchpoint", "green")),
            ("wr", watcher.remove_watchpoint,                              "wr"+colored(" <addr>            ", "yellow") + colored("Remove watchpoint", "green")),
    ]

    def load_angr(self):
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Importing angr", "yellow"))
        import angr
        import claripy
        self.angr = angr
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Loading r2angr", "yellow"))
        self.is_initialized = True

        self.project = angr.Project(self.binary)
        self.fast_project = angr.Project(self.binary, auto_load_libs=False)
        state = self.project.factory.entry_state(args=self.argv, stdin=self.stdin)
        self.simgr = self.project.factory.simgr(state)

        try:
            self.r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))
        except:
            self.r2p.cmd("s " + hex(state.solver.eval(state.regs.eip)))

        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr at entry point", "yellow"))

    def initialize_entry(self):
        self.project = self.angr.Project(self.binary)
        self.fast_project = self.angr.Project(self.binary, auto_load_libs=False)
        state = self.project.factory.entry_state(args=self.argv, stdin=self.stdin)
        self.simgr = self.project.factory.simgr(state)
        self.r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))
        print(colored("[", "yellow") + colored("R2ANGR", "green") + colored("] ", "yellow") + colored("Initialized r2angr at entry point", "yellow"))

    def __init__(self, binary, r2p):
        self.stdin = claripy.BVS("stdin", 20*8)
        self.binary = binary
        self.r2p = r2p

    def run(self, command):
        command = command.split(" ")

        if "i" == command[0] and False:
            self.initialize_entry()
            self.is_initialized = True
            return

        self.command = command
        self.debugger.r2angr = self
        self.stash.r2angr = self
        self.watcher.r2angr = self
        self.hooks.r2angr = self
        self.initializer.r2angr = self
        self.bitvectors.r2angr = self

        found = False
        for c, f, h in self.commands:
            if c == command[0]:
                if not self.is_initialized:
                    print("r2angr not initialized, use the mi command")
                else:
                    self.return_value = ""
                    f()
                    if not c == "s" and not c == "sl":
                        self.update_highlight()
                found = True

        if not found or "?" in command:
            self.help(command)

    def help(self, command):
        self.return_value = ""
        command[0] = command[0].replace("?", "")
        print("Getting help")
        for c, f, h in self.commands:
            if command[0] in c.split(" ")[0].replace("?", "") and len(c) - len(command[0]) < 2:
                print("| M" + h)

    def update_highlight(self):
        for comment in self.r2p.cmdj("CCj"):
            if "r2angr" in comment["name"]:
                self.r2p.cmd("CC- @ " + hex(comment["offset"]))
                self.r2p.cmd("ecH- @ " + hex(comment["offset"]))

        i = 0
        for state in self.simgr.deadended:
            self.r2p.cmd("ecHi red @ " + hex(state.addr))
            self.r2p.cmd("CC- @ " + hex(state.addr))
            self.r2p.cmd("CC+r2angr \"deadended\" state " + str(i) + " @ " + hex(state.addr))
            if not "invalid" in self.r2p.cmd("pd 2 @ " + hex(state.addr)):
                self.r2p.cmd("s " + hex(state.addr))
            i += 1

        i = 0
        for state in self.simgr.active:
            self.r2p.cmd("ecHi blue @ " + hex(state.addr))
            self.r2p.cmd("CC- @ " + hex(state.addr))
            self.r2p.cmd("CC+r2angr \"active\" state " + str(i) + " @ " + hex(state.addr))
            if not "invalid" in self.r2p.cmd("pd 2 @ " + hex(state.addr)):
                self.r2p.cmd("s " + hex(state.addr))
            i += 1

        for addr in self.watcher.watchpoints:
            count, name = self.watcher.watchpoints[addr]
            self.r2p.cmd("ecHi magenta @ " + hex(addr))
            self.r2p.cmd("CC- @ " + hex(addr))

            if count > 0:
                self.r2p.cmd("CC+Watchpoint " + name + " @ " + hex(addr))
            else:
                self.r2p.cmd("CC+Watchpoint " + name + "(Hits: " + str(count) + ") @ " + hex(addr))

