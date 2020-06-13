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

### Example

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

Since the state we acare about is at `0x400844`, we know our password is "Code_Talkers".
