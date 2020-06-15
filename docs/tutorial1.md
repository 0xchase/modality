# Basic Exploration

The following tutorials will use binaries from the angr_ctf by *jakespringer* (included in the challenges/ folder) until I have time to write my own. We'll start with the first one, 00_angr_find.

We'll start by opening and analyzing the binary with radare2.

```
chase@chase:~/github/r2angr/docs/challenges$ r2 00_angr_find 
 -- Use rarun2 to launch your programs with a predefined environment.
[0x08048450]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

Looking at the main function, we can see that there's a function to mangle the user input and a strcmp() followed by a branch for success/failure.

```
│           0x0804865c      e86ffdffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│           0x08048661      83c410         add esp, 0x10
│           0x08048664      85c0           test eax, eax
│       ┌─< 0x08048666      7412           je 0x804867a
│       │   0x08048668      83ec0c         sub esp, 0xc
│       │   0x0804866b      6833870408     push str.Try_again.         ; 0x8048733 ; "Try again." ; const char *s
│       │   0x08048670      e88bfdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x08048675      83c410         add esp, 0x10
│      ┌──< 0x08048678      eb10           jmp 0x804868a
│      ││   ; CODE XREF from main @ 0x8048666
│      │└─> 0x0804867a      83ec0c         sub esp, 0xc
│      │    0x0804867d      6860870408     push str.Good_Job.          ; 0x8048760 ; "Good Job." ; const char *s
│      │    0x08048682      e879fdffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x08048687      83c410         add esp, 0x10
│      │    ; CODE XREF from main @ 0x8048678
│      └──> 0x0804868a      b800000000     mov eax, 0
│           0x0804868f      8b4df4         mov ecx, dword [canary]
```

Solving this manually would require reversing the `sym.complex_function` function. Instead, we can simply explore to the success branch, then print the stdin for that state. First we'll explore to the correct branch.

```
:> Meu 0x804867a
[DEBUG] Starting exploration. Find: [0x804867a]
WARNING | 2020-06-15 17:07:08,625 | angr.state_plugins.symbolic_memory | Filling memory at 0x804a040 with 240 unconstrained bytes referenced from 0x90512d0 (printf+0x0 in libc.so.6 (0x512d0))
WARNING | 2020-06-15 17:07:09,815 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffefffc with 103 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
WARNING | 2020-06-15 17:07:09,815 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff70 with 4 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
[DEBUG] Found 1 solutions
```

Then we'll list the states. We can see that there are two active states and 15 deadended states.

```
:> Msl
Active states:
  0 0x8048400
  1 0x804867a

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
```

Since we only care about the state at `0x804867a`, we can kill state 0.

```
:> Msl
Active states:
  0 0x804867a

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
  16 0x8048400
```

Finally, we can print stdin for the remaining state.

```
:> Msi
Active state 0 at 0x804867a:
QTMPXTYU
```

We can then test this against our binary to make sure it is correct!

```
[0x0804867a]> q
shell@shell:~/github/modality/docs/challenges$ ./00_angr_find 
placeholder
Enter the password: QTMPXTYU
Good Job.
```
