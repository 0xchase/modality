# Modality

This project is still in development so bugs and missing features are expected. If you find one, feel free to create an issue.

---

## About

A radare2 plugin to quickly perform symbolic execution inside radare2 with angr, a platform-agnostic binary analysis framework by the Computer Security Lab at UC Santa Barbara and SEFCOM at Arizona State University. This plugin is intended to integrate angr in a way that's (relativley) consistent with the r2cli conventions

### Goals

This project intends to
 - Better integrate symbolic execution with the rest of the reverse engineering process
 - Provide a faster/simpler alternative to using angr than the python bindings
 - Allow for switching between concrete and symbolic execution (this feature is coming soon)
 - Provide useful visualizations of the angr backend
 - Allow for interactive and fine grained control over angr execution
 - Include a suite of commands for vulnerability detection, exploit generation, etc (coming soon)
 - Have long term support

---

## Features

### Documentation
 - [ ] Document installation
 - [ ] Wiki and tutorial
 - [ ] Short tool overview
 - [ ] Long tutorial video

### Emulation
 - [x] Basic initialization: `mi`
 - [ ] Initialize at arbitrary memory location
 - [ ] Add all the exploration methods
 - [ ] Symbolize arbitrary number of arguments (use -d arguments to set them initially)
 - [ ] Initialize on function with current debugger args, specific args, or symbolic args
 - [x] Basic emulation: `mc`, `mcs`, `mcb`, `mcu`, `mco`
 - [x] Basic exploration: `me`, `meu`
 - [ ] Explore for certain output
 - [ ] Implement staged exploration
 - [ ] Add avoid/find annotation commands
 - [x] Basic watchpoint commands: `mw`, `mwl`
 - [ ] More watchpoint commands (remove watchpoints, run command at watchpoints)
 - [ ] Switch between concrete and symbolic execution

### Stash manipulation
 - [x] Basic state manipulation: `ms`, `msl`, `msk`, `msr`, `mse`, `mss`
 - [x] Group state operations: `mska`, `msra`
 - [x] Print more detailed state information
 - [ ] Print info while killing/reviving/extracting states
 - [ ] Kill/revive based on output
 - [ ] State seeking by index
 - [x] States outputs and inputs printing
 - [ ] Print even more detailed state information (current function, ...)

### Symbolize commands
 - [ ] Commands to symbolize registers or stack values with different data types
 - [ ] Commands to symbolize variables

### Visualization
 - [ ] PEDA like view option
 - [ ] Finalize found/active highlighting and stashing
 - [ ] Indent all printing according to call/loop hierarchy
 - [ ] Implement custom radare2 panels view for exploration
 - [ ] Print log of a state history
 - [ ] If enabled, replace commands like `dr` with symbolic information
 - [ ] Graph an emulation history, with branches at state splitting and annotations for loops, branches, etc
 - [ ] Standardize print messages with formats like [DEBUG] [PRINT] [HOOK] etc
 - [ ] Command to print detailed info about state at current address. Can be used with visual panels mode.
 - [ ] Annotate graph with state split locations

### Exploitation
 - [ ] Brainstorm list of features
 - [ ] Integrate or reimplement functionality of rex

### Hooks
 - [x] Analysis commands for loops, functions, etc
 - [x] Move analysis commands to the hook clasification
 - [ ] List hooks
 - [ ] When hooking function calls, print args
 - [ ] Print function return values
 - [ ] Command to add hooks at locations, run some r2 command there
 - [ ] When state splits, print [1|2] => [1|3] with split address
 - [ ] Add custom hooks for strlen, etc that ask for length or arbitrary length. Can also set this in the config.

### Other
 - [ ] Deal with offets for PIE
 - [ ] Commands to edit config.txt file
 - [ ] Integrate ghidra with the disassembler
 - [ ] Watchpoint comment hit count doesn't work
 - [ ] Watchpoint hits should work per state
 - [ ] Remove watchpoints unimplemented
 - [ ] der command broken
 - [ ] Tools for dealing with path explosion
 - [ ] Get working as scripting engine
 - [ ] Easy way to edit script inside radare2 that runs at the beginning. Can add custom hooks this way.
 - [ ] Make commands robust, go through and check for bugs
 - [ ] Write wiki for this project. Write tutorial for this project

---

### Short Tutorial

First we'll open one of the example binaries in radare2 and display the help with the `M?` command.

```
shell@shell:~/$ r2 challenges/r100 
[0x00400610]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00400610]> M?
[R2ANGR] Importing angr
[R2ANGR] Loading r2angr
[R2ANGR] Initialized r2angr at entry point
Getting help
| Mc[?]                 Continue emulation
| Me[?]                 Explore using find/avoid comments
| Mi[?]                 Initialize at entry point
| Ms[?]                 States list
| Mh[?]                 Hooks
| Mw[?] <addr>          Add a watchpoint
[0x00400610]> 
```

The first time you run a modality command, it will take a few seconds to load angr, and automatically initialize the project at the entry point. Next, we'll list the commands relevant to emulation with `Me?`.

```
[0x00400610]> Me?
Getting help
| Me[?]                 Explore using find/avoid comments
| Meu <addr>            Explore until address
[0x00400610]> 
```

We'll use the `Meu` command to explore until one of the simulation manager states hits the main function. 

```
[0x00400610]> Meu main
[DEBUG] Starting exploration. Find: [0x4007e8]
[DEBUG] Found 1 solutions
[0x004007e8]> 
```

As we can see, one of our states found the main function. We can list all the active states with `Msl`.

```
[0x004007e8]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4
  2 0x4007e8

[0x004007e8]> 
```

Since we only care about the state at `0x4007e8`, we can kill the states at `0x4007e4` with the `Msk` command (to kill a single state) or the `Mse` command (to extract a single state and kill all the others).

```
[0x004007e8]> Mse 2
[0x004007e8]> Msl
Active states:
  0 0x4007e8

Deadended states:
  0 0x4007e4
  1 0x4007e4
```

This binary contains a success/fail condition. We want to know the input that produces the success condition. We can explore to this branch as shown below.

```
[0x004007e8]> Meu 0x00400844
[DEBUG] Starting exploration. Find: [0x400844]
[DEBUG] Found 1 solutions
[0x00400844]> 
```

We can then list the stdin for all active states with `Msi`.

```
[0x00400844]> Msi
Active state 0 at 0x4005a0:
b'Code_Talker\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
Active state 1 at 0x40085f:
b'Code_Talke\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
Active state 2 at 0x40087f:
b'Code_Talk\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
Active state 3 at 0x4000050:
b'Code_Tal\xf5\xe5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
Active state 4 at 0x400844:
b'Code_Talkers\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
```

Since the state we acare about is at `0x400844`, we know our password is "Code_Talkers". To explain a variety of features we took a long way to solve this challenge, it could be solved quicker by opening r2 and using the one liner below.

```
[0x00400610]> aa;Meu 0x400844;Mse 0x400844;Msi
[x] Analyze all flags starting with sym. and entry0 (aa)
[R2ANGR] Importing angr
[R2ANGR] Loading r2angr
[R2ANGR] Initialized r2angr at entry point
[DEBUG] Starting exploration. Find: [0x400844]
[DEBUG] Found 1 solutions
Active state 0 at 0x400844:
b'Code_Talkers\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
[0x00400844]> 
```
