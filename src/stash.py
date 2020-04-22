from tabulate import *

# Chage commands to kill/revive state by numbers rather than addresses

# ========== Commands ========== #

def kill(main, command, simgr):
    if "0x" in command[1]:
        addr = int(command[1], 16)
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == addr)
    else:
        num = int(command[1])
        simgr.deadended.append(simgr.active[num])
        simgr.active.remove(simgr.active[num])

def drop(main, command, simgr):
    print("Dropping deadended stash")
    simgr.drop(stash="deadended")
        
def save(main, command, simgr):
    if "0x" in command[1]:
        addr = int(command[1], 16)
        simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr != addr)
    else:
        num = int(command[1])
        temp = simgr.active[num]
        for s in simgr.active:
            simgr.deadended.append(s)
        simgr.active = []
        simgr.active.append(temp)
        simgr.deadended.remove(temp)

def revive(main, command, simgr):
    addr = int(command[1], 16)
    simgr.move(from_stash='deadended', to_stash='active', filter_func=lambda s: s.addr == addr)

def list(main, command, simgr):
    table = []
    if len(command) == 1:
        for i in range(0, len(simgr.active)):
            table.append([str(i), hex(simgr.active[i].addr)])
    print(tabulate(table))

def name(main, command, simgr):
    print("Stash name")

def stdout(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active:
            print_decode(state.posix.dumps(1))

def stdin(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active:
            print_decode(state.posix.dumps(0))
    else:
        print_decode(simgr.active[int(command[1])].posix.dumps(0))

def stdout_all(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active + simgr.deadended:
            print_decode(state.posix.dumps(1))
    else:
        print_decode(simgr.active[int(command[1])].posix.dumps(1))

def stdin_all(main, command, simgr):
    if len(command) == 1:
        for state in simgr.active + simgr.deadended:
            print_decode(state.posix.dumps(0))

def revive_all(main, command, simgr):
    for state in simgr.deadended:
        simgr.active.append(state)
    simgr.deadended = []

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

def kill_all(main, command, simgr):
    print("Killing all states")
    i = 0
    while i < len(simgr.active):
        state = simgr.active[i]
        simgr.deadended.append(state)
        simgr.active.remove(state)

def auto_kill_stdout(main, command, simgr):
    print("Auto killing states with output")

# ========== Utilities ========== #

def get_name(state):
    if hasattr(state, "name"):
        return state.name
    else:
        return hex(state.addr)

def print_decode(data):
    try:
        print(data.decode())
    except:
        print(str(data))
