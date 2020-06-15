# Overview

This plugin is built on top of angr, and so most of it's functionality revolves around angr conventions. It would be useful for anyone who uses this tool to read the angr docs first. 

## Introduction

Radare2's design is ideal for integration with angr because it allows for complicated command structures. All Modality commands are prefixed with `M`, and the top level commands can be listed with `M?`.

```
[0x08048450]> M?
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
[0x08048450]> 
```

This first time you run a Modality command it imports angr and loads the rest of the plugin which normally takes a few seconds. This is only required once per radare2 session. 

We can see the command above listed the top level commands for exploration, state manipulation, etc. We can list the sub-commands for any top level command as shown below.

```
[0x08048450]> Me?
Getting help
| Me[?]                 Explore using find/avoid comments
| Meu <addr>            Explore until address
| Meo <string>          Explore until string is in stdout
[0x08048450]> 
```

This should all be mostly consistent with the r2cli conventions.

## Example

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

It takes a second to load angr and the rest of the plugin, then displays our top level help menu. During this load, it automatically initializes a state at the entry point, so our next step is to explore to the desired address. We can list the exploration commands as shown below. 

```
[0x00400610]> Me?
Getting help
| Me[?]                 Explore using find/avoid comments
| Meu <addr>            Explore until address
| Meo <string>          Explore until string is in stdout
[0x00400610]> 
```

We'll use the `Meu` command to *explore until* one of the simulation manager states hits the main function. 

```
[0x00400610]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
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

Since we only care about the state at `0x4007e8` (the others are stuck at an anti-debugging trick), we can kill the states at `0x4007e4` with the `Msk` command (to *kill* a single state) or the `Mse` command (to *extract* a single state and kill all the others).

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

Since the state we acare about is at `0x400844`, we know our password is "Code_Talkers". 

### Quicker solution

To explain a variety of features we took a long way to solve this challenge, it could be solved quicker by opening r2 and using the one liner below.

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
