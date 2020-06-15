# Finding and Avoiding

For this challenge we'll use a different find/avoid technique. The challenge is 01_angr_avoid. We'll start by opening the binary and doing some basic analysis.

```
shell@shell:~/github/modality/docs/challenges$ r2 01_angr_avoid 
[0x08048430]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x08048430]> s main
[0x08048602]> 
```

The graph of the main function takes a while to render, so you may want to avoid that. Scrolling through the visual mode, we can see it gets some user input, calls `sym.complex_function`, then there's a lot of branches with calls to `sym.avoid_me` and `sym.maybe_good`. We'll seek to the first function and add a comment there that says "avoid". You can seek there and add a comment using `;` from visual mode, or add a comment with the `CC+` command. Once our avoid comment is added we'll seek to the `sym.maybe_good` function, and add a comment that says "find" on the branch that prints "Good Job.". 

Next we can run the `Me` commmand, which collects the addresses marked by find/avoid and explores using those locations.

```
[0x080485b5]> Me
[R2ANGR] Importing angr
[R2ANGR] Loading r2angr
[R2ANGR] Initialized r2angr at entry point
[DEBUG] Starting exploration.
Find: [0x80485dd]. Avoid: [0x80485a8].
WARNING | 2020-06-15 17:24:37,083 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-06-15 17:24:37,083 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-06-15 17:24:37,083 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-06-15 17:24:37,083 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-06-15 17:24:37,083 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-06-15 17:24:37,084 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80d45e1 (__libc_csu_init+0x1 in 01_angr_avoid (0x80d45e1))
WARNING | 2020-06-15 17:24:37,086 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80d45e3 (__libc_csu_init+0x3 in 01_angr_avoid (0x80d45e3))
WARNING | 2020-06-15 17:24:37,437 | angr.state_plugins.symbolic_memory | Filling memory at 0x80d6040 with 240 unconstrained bytes referenced from 0x90512d0 (printf+0x0 in libc.so.6 (0x512d0))
WARNING | 2020-06-15 17:24:39,695 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffefffc with 72 unconstrained bytes referenced from 0x907e8c0 (strncmp+0x0 in libc.so.6 (0x7e8c0))
WARNING | 2020-06-15 17:24:39,695 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff70 with 4 unconstrained bytes referenced from 0x907e8c0 (strncmp+0x0 in libc.so.6 (0x7e8c0))
WARNING | 2020-06-15 17:24:39,696 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff4d with 11 unconstrained bytes referenced from 0x907e8c0 (strncmp+0x0 in libc.so.6 (0x7e8c0))
WARNING | 2020-06-15 17:24:39,707 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fff0044 with 20 unconstrained bytes referenced from 0x907e8c0 (strncmp+0x0 in libc.so.6 (0x7e8c0))
[DEBUG] Found 1 solutions
[0x080485dd]> 
```

After a few seconds, we get a solution. We can list the states with the `Msl` command, and kill the unwanted active state as shown below.

```
[0x080485dd]> Msk 0
[0x080485dd]> Msl
Active states:
  0 0x80485dd

Deadended states:
  0 0x90303d0
  1 0x90303d0
  2 0x90303d0
  3 0x90303d0
  4 0x90303d0
  5 0x90303d0
  6 0x90303d0
  7 0x90303d0
  8 0x90303d0
  9 0x90303d0
  10 0x90303d0
  11 0x90303d0
  12 0x90303d0
  13 0x90303d0
  14 0x90303d0
  15 0x90303d0
  16 0x80483d0

[0x080485dd]> 
```

We can then print the stdin of the remaining state with the `Msi` command.

```
[0x080485dd]> Msi
Active state 0 at 0x80485dd:
RNGFXITY
```

This password can be checked against the binary.

```
[0x080485dd]> q
chase@chase:~/github/r2angr/docs/challenges$ ./01_angr_avoid 
placeholder
Enter the password: RNGFXITY
Good Job.
```
