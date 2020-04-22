#!/usr/bin/python3

import sys

if len(sys.argv) < 2:
    print("Usage: ./tool.py <binary> <arg count>")
    exit()

import angr
import claripy

sys.path.append("src/")

# Import rest of code base
import stash
from debug import *
from disass import *
from printer import *
from hooks import *
from util import *
from hooks import *
from analysis import *

print("Imported libraries")

filename = sys.argv[1]
project = None
simgr = None
state = None
argv = None
stdin = None

def debugger_initialize(addr):
    global project
    global simgr
    global state
    global stdin
    global argv

    stdin = claripy.BVS("stdin", 0x2c*8)
    argv = []

    argv.append(sys.argv[1])
    arg_num = 0

    if len(sys.argv) > 2:
        print("Symbolizing arugments")
        arg_num = int(sys.argv[2])

    for i in range(0, arg_num):
        sym_arg = claripy.BVS("sym_arg" + str(i), 20*8)
        argv.append(sym_arg)

    print(str(argv))

    project = angr.Project(filename)
    #state = project.factory.entry_state(args=argv, stdin=stdin, add_options=angr.options.unicorn)

    if addr == "entry0":
        state = project.factory.entry_state(args=argv, stdin=stdin)
    else:
        state = project.factory.blank_state(addr=int(addr, 16), args=argv, stdin=stdin)

    simgr = project.factory.simgr(state, veritesting=False)

    state.history_arr = []

    for b in stdin.chop(8):
        #state.solver.add(b > 0x20)
        #state.solver.add(b < 0x7f)
        #state.solver.add(b > 43)
        state.solver.add(b < 127)

    state.solver.add(stdin.chop(8)[len(stdin.chop(8))-1] == '\x00')

    @project.hook(0x400990, length=0)
    def hashmenot_regs(state):
        state.regs.rax = claripy.BVV(0x51, 64)
        state.regs.rdi = claripy.BVV(0x51, 64)

    for sym_arg in argv[1:]:
        print("Constraining argument to ascii range")
        for b in sym_arg.chop(8):
            state.solver.And(b >= ord(' '), b <= ord('~'))
            #state.solver.add(b != '\x80')

debugger_initialize("entry0")

disassembler = Disassembler(filename)
debugger = Debugger(disassembler.functions)
printer = Printer()
hooks = Hooks()

analysis = Analysis()

debugger_commands = [
            ("dc", debugger.debug_continue),
            ("dcu", debugger.debug_continue_until),
            ("dco", debugger.debug_continue_output),
            ("ds", debugger.debug_step),
            ("dw", debugger.debug_watch),
            ("dm", debugger.debug_merge),
            ("dcb", debugger.debug_continue_until_branch),
            ("der", debugger.debug_explore_revert),
            ("deu", debugger.debug_explore_until),
            ("deul", debugger.debug_explore_until_loop),
            ("del", debugger.debug_explore_loop),
            ("deud", debugger.debug_explore_until_dfs),
            ("deo", debugger.debug_explore_stdout),
            ("dr", debugger.debug_registers),
            ("dp", debugger.debug_print),
            ("df", debugger.debug_function),
            ("doo", debugger.debug_initialize)]

disassembler_commands = [
            ("pd", disassembler.disassemble)]

stash_commands = [
            ("sl", stash.list),
            ("sk", stash.kill),
            ("ss", stash.save),
            ("sko", stash.kill_stdout),
            ("ska", stash.kill_all),
            ("sr", stash.revive),
            ("sro", stash.revive_stdout),
            ("sra", stash.revive_all),
            ("sd", stash.drop),
            ("sn", stash.name),
            ("si", stash.stdin),
            ("sia", stash.stdin_all),
            ("so", stash.stdout),
            ("soa", stash.stdout_all)]

print_commands = [
            ("pa", printer.args),
            ("paa", printer.args_all),
            ("po", printer.stdout),
            ("poa", printer.stdout_all),
            ("pi", printer.stdin),
            ("ps", printer.states),
            ("psh", printer.states_history),
            ("psc", printer.states_constraints),
            ("pse", printer.states_events),
            ("psp", printer.states_path),
            ("pst", printer.states_tree),
            ("pia", printer.stdin_all)]

analysis_commands = [
            ("aaa", analysis.aaa)
            ]

util_commands = [
            ("c", clear),
            ("q", exit)]


def command_line():
    global simgr
    global debugger
    global project
    global argv
    global hooks

    while True:
        print(colored("[" + get_addr() + "|", "yellow") + colored(str(len(simgr.deadended)), "red") + colored("]> ", "yellow"), end='')
        command = input().strip().split(" ")
        if "di" == command[0]:
            if len(command) < 2:
                debugger_initialize("entry0")
            else:
                debugger_initialize(command[1])

        for cmd, function in debugger_commands:
            if cmd == command[0]:
                debugger.project = project
                debugger.simgr = simgr
                debugger.command = command
                debugger.filename = filename
                debugger.angr = angr
                debugger.loop_entry_addrs = hooks.loop_entry_addrs
                function()
        for cmd, function in disassembler_commands:
            if cmd == command[0]:
                disassembler.simgr = simgr
                disassembler.command = command
                function()
        for cmd, function in stash_commands:
            if cmd == command[0]:
                function(lambda: null, command, simgr)
        for cmd, function in util_commands:
            if cmd == command[0]:
                function()
        for cmd, function in print_commands:
            if cmd == command[0]:
                printer.command = command
                printer.argv1 = argv
                printer.simgr = simgr
                printer.stdin = stdin
                function()
        if command[0] == "a":
            print("Analyzing function calls")
            analysis.colored = colored
            hooks.project = project
            hooks.simgr = simgr
            hooks.filename = filename
            hooks.colored = colored
            hooks.angr = angr
            hooks.functions = disassembler.functions
            hooks.library_functions = disassembler.library_functions
            hooks.setup_functions()
        if command[0] == "aa":
            print("Analyzing fucntion calls and loops")
            analysis.colored = colored
            hooks.project = project
            hooks.simgr = simgr
            hooks.filename = filename
            hooks.colored = colored
            hooks.angr = angr
            hooks.functions = disassembler.functions
            hooks.library_functions = disassembler.library_functions
            hooks.setup_functions()

            hooks.setup_loops(angr, project, simgr, filename, colored)
        if command[0] == "aaa":
            print("Analyzing function calls, loops, and memory read/writes")
            analysis.colored = colored
            hooks.project = project
            hooks.simgr = simgr
            hooks.filename = filename
            hooks.colored = colored
            hooks.angr = angr
            hooks.functions = disassembler.functions
            hooks.library_functions = disassembler.library_functions
            hooks.setup_functions()

            hooks.setup_loops(angr, project, simgr, filename, colored)

            analysis.simgr = simgr
            analysis.angr = angr
            analysis.aaa()

def get_addr():
    ret = ""
    if len(simgr.active) < 4:
        for s in simgr.active:
            ret += str(hex(s.addr)) + " "
        ret = ret[0:-1]
    else:
        ret += str(len(simgr.active))
    return ret

if __name__ == "__main__":
    command_line()
