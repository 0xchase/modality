# Bitvector basics

For this challenge we'll experiment with symbolizing registers and initializing at a different location than the entry point. We'll start by opening the binary and running some analysis.

```
shell@shell:~/github/r2angr/docs/challenges$ r2 03_angr_symbolic_registers 
 -- A git pull a day keeps the segfault away
[0x080483f0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x080483f0]> s main
[0x080488a6]> 
```

Looking at the main function we can see it calls a `sym.get_user_input()` function, which calls scanf with "%x %x %s". In previous challenges we relied on angr to automatically symbolize stdin, but angr doesn't know how to deal with multiple stdin values automatically. Since the three inputs end up in eax, ebx, and edx, we'll try initializing after the function, symbolizing the registers manually, and then exploring as normal.

First we'll initialize a blank state at `0x80488d1`, after the call to `sym.get_user_input`. 

```
[0x080488a6]> Mi
[R2ANGR] Importing angr
[R2ANGR] Loading r2angr
[R2ANGR] Initialized r2angr at entry point
WARNING | 2020-06-15 17:54:43,382 | angr.sim_state | Unused keyword arguments passed to SimState: args
[0x080488a6]> Mib @ 0x80488d1
[R2ANGR] Initialized r2angr blank state at current address
[0x080488a6]> 
```

Then we'll symbolize the three registers with bitvectors using the `Mbr` command.

```
[0x080488a6]> Mbr eax
Symbolizing eax in active state 0 at 0x80483f0
[0x080483f0]> Mbr ebx
Symbolizing ebx in active state 0 at 0x80483f0
[0x080483f0]> Mbr edx
Symbolizing edx in active state 0 at 0x80483f0
[0x080483f0]> 
```

And we'll explore to the success branch.

```
:> Meu 0x8048937
[DEBUG] Starting exploration. Find: [0x8048937]
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-06-15 17:58:01,969 | angr.state_plugins.symbolic_memory | Filling register ebp with 4 unconstrained bytes referenced from 0x80488d1 (main+0x2b in 03_angr_symbolic_registers (0x80488d1))
WARNING | 2020-06-15 17:58:01,970 | angr.state_plugins.symbolic_memory | Filling register eax with 4 unconstrained bytes referenced from 0x80488d1 (main+0x2b in 03_angr_symbolic_registers (0x80488d1))
WARNING | 2020-06-15 17:58:02,007 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80488d4 (main+0x2e in 03_angr_symbolic_registers (0x80488d4))
WARNING | 2020-06-15 17:58:02,020 | angr.state_plugins.symbolic_memory | Filling register edx with 4 unconstrained bytes referenced from 0x80488d7 (main+0x31 in 03_angr_symbolic_registers (0x80488d7))
[DEBUG] Found 1 solutions
```

We can list the active states.

```
:> Msl
Active states:
  0 0x80483b0
  1 0x9067b40
  2 0x8048932
  3 0x8048937
```

Since we only care about the one at `0x8048937`, we'll extract it and kill the others using the `Mse` command and the index.

```
:> Mse 3
:> Msl
Active states:
  0 0x8048937

Deadended states:
  0 0x80483b0
  1 0x9067b40
  2 0x8048932
```

Finally, we'll solve our bitvectors (which were used to symbolize the registers) using the `Mbs` command.

```
:> Mbs
3674319863
1227938937
3514688974
```

If we convert these to hex (since stdin used "%x %x %x"), we get `db01abf7`, `4930dc79`, and `d17de5ce`. Let's try these as inputs to the binary.

```
[0x08048937]> q
shell@shell:~/github/r2angr/docs/challenges$ ./03_angr_symbolic_registers 
placeholder
Enter the password: db01abf7 4930dc79 d17de5ce
Good Job.
shell@shell:~/github/r2angr/docs/challenges$ 
```
