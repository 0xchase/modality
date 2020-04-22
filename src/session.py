#!/usr/bin/python3

import angr
import claripy

import stash
from debug import *
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

# Get rid of classes, import all of them into sessions class
# 

class Session():
    stdin = ""
    argv = []
    command = ""

    debugger = Debugger(None)

    commands = [
            # Debugger
            # Continue, continue until, continue until branch, explore until, explore
            ("c", debugger.debug_continue),
            ("cu", debugger.debug_continue_until),
            ("cub", debugger.debug_continue_until_branch),
            ("co", debugger.debug_continue_output),
            ("eu", debugger.debug_explore_until),
            ("e", debugger.debug_explore),
            
            # Stash
            ("sl", stash.list),
            ("sk", stash.kill),
            ("ss", stash.save),
    ]

    def __init__(self, binary, r2p):
        print("Initialized r2-angr")
        self.stdin = claripy.BVS("stdin", 20*8)
        self.r2p = r2p

        self.binary = binary
        self.project = angr.Project(binary)
        state = self.project.factory.entry_state(args=self.argv, stdin=self.stdin)
        self.simgr = self.project.factory.simgr()
        r2p.cmd("s " + hex(state.solver.eval(state.regs.rip)))

    def run(self, command):
        command = command.split(" ")
        self.command = command
        self.debugger.session = self

        for c, f in self.commands:
            if c == command[0]:
                print("Calling function")
                f()

