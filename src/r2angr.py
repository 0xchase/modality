#!/usr/bin/python3

from debug import *
from stash import *
from disass import *
from printer import *
from hooks import *
from util import *
from analysis import *

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
    return_value = ""

    commands = [
            ("a", debugger.debug_continue,                  "a" + colored("[?]              ", "yellow") + colored("Basic analysis", "green")),
            ("c", debugger.debug_continue,                  "c" + colored("[?]              ", "yellow") + colored("Continue emulation", "green")),
            ("e", debugger.debug_explore,                  "e" + colored("[?]              ", "yellow") + colored("Explore using find/avoid comments", "green")),
            ("i", None,                                     "i" + colored("[?]              ", "yellow") + colored("Initialize at entry point", "green")),
            ("s", stash.list,                  "s" + colored("[?]              ", "yellow") + colored("States list", "green")),

            ("cs", debugger.debug_step,           "cu" + colored(" <addr>         ", "yellow") + colored("Continue emulation until address", "green")),
            ("cu", debugger.debug_continue_until,           "cu" + colored(" <addr>         ", "yellow") + colored("Continue emulation until address", "green")),
            ("cb", debugger.debug_step,    "cb                " + colored("Continue emulation one basic block", "green")),
            ("co", debugger.debug_continue_output,          "co                " + colored("Continue emulation until output", "green")),

            ("eu", debugger.debug_explore_until,            "eu" + colored(" <addr>         ", "yellow") + colored("Explore until address", "green")),

            ("sl", stash.list,                              "sk"+colored(" <index>        ", "yellow") + colored("Kill state by index", "green")),
            ("sk", stash.kill,                              "sk"+colored(" <index>        ", "yellow") + colored("Kill state by index", "green")),
            ("sr", stash.revive,                              "sr"+colored(" <index>        ", "yellow") + colored("Kill state by index", "green")),
            ("ss", stash.save,                              "ss"+colored(" <index>        ", "yellow") + colored("Save only this state by index", "green")),
    ]

    def initialize2(self):
        print("Initializing state")
        import angr
        import claripy

        self.project = angr.Project(self.binary)
        state = self.project.factory.entry_state(args=self.argv, stdin=self.stdin)
        self.simgr = self.project.factory.simgr(state)
        self.r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))
        print("Initialized r2angr")

    def __init__(self, binary, r2p):
        self.stdin = claripy.BVS("stdin", 20*8)
        self.binary = binary
        self.r2p = r2p

    def run(self, command):
        command = command.split(" ")

        if "i" == command[0]:
            self.initialize2()
            self.is_initialized = True
            return

        self.command = command
        self.debugger.r2angr = self
        self.stash.r2angr = self

        found = False
        for c, f, h in self.commands:
            if c == command[0]:
                if not self.is_initialized:
                    print("r2angr not initialized, use the mi command")
                else:
                    try:
                        self.simgr.unstash(from_stash="found", to_stash="active")
                    except:
                        pass
                    self.return_value = ""
                    f()
                    self.update_highlight()
                found = True
        if not found or "?" in command:
            self.help(command)

    def help(self, command):
        command[0] = command[0].replace("?", "")
        print("Getting help")
        for c, f, h in self.commands:
            if command[0] in c.split(" ")[0].replace("?", "") and len(c) - len(command[0]) < 2:
                print("| m" + h)

    def update_highlight(self):
        for comment in self.r2p.cmdj("CCj"):
            if "r2angr" in comment["name"]:
                self.r2p.cmd("CC- @ " + hex(comment["offset"]))
                self.r2p.cmd("ecH- @ " + hex(comment["offset"]))
        for state in self.simgr.active:
            print(hex(state.addr))
            self.r2p.cmd("ecHi cyan @ " + hex(state.addr))
            self.r2p.cmd("CC- @ " + hex(state.addr))
            self.r2p.cmd("CC+r2angr active @ " + hex(state.addr))
            self.r2p.cmd("s " + hex(state.addr))
        for state in self.simgr.found:
            print(hex(state.addr))
            self.r2p.cmd("ecHi green @ " + hex(state.addr))
            self.r2p.cmd("CC- @ " + hex(state.addr))
            self.r2p.cmd("CC+r2angr found @ " + hex(state.addr))
            self.r2p.cmd("s " + hex(state.addr))
        self.r2p.cmd("r")

