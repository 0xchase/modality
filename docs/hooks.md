# Hooks

These command can be used to hook different parts of the code and run commands or print debugging information when a state hits those locations. This code is mostly proof-of-concept so a lot of features are currently missing.

The relevant commands can be listed using `Mh?`.

```
[0x00400610]> Mh?
Getting help
| Mh[?]                  Hooks help
| Mhf                    Hook all functions
| Mhl                    Hook all loops
[0x00400610]> 
```

## Hooking functions

An example of the `Mhf` command for hooking all functions is shown below.

```
[0x00400610]> Mhf
[HOOKS] Hooking function: entry0 at 0x400610
[HOOKS] Hooking import: sym.imp.__libc_start_main at 0x4005d0
[HOOKS] Hooking import: sym.imp.getenv at 0x400590
[HOOKS] Hooking import: sym.imp.puts at 0x4005a0
[HOOKS] Hooking import: sym.imp.__stack_chk_fail at 0x4005b0
[HOOKS] Hooking import: sym.imp.printf at 0x4005c0
[HOOKS] Hooking import: sym.imp.fgets at 0x4005e0
[HOOKS] Hooking import: sym.imp.ptrace at 0x400600
[HOOKS] Hooking function: main at 0x4007e8
[HOOKS] Hooking function: entry.init0 at 0x4006d0
[HOOKS] Hooking function: entry.init1 at 0x4007a8
[HOOKS] Hooking function: entry.fini0 at 0x4006b0
[HOOKS] Hooking function: fcn.00400640 at 0x400640
[0x00400610]> Meu 0x400844
[DEBUG] Starting exploration. Find: [0x400844]
[HOOKS] Called entry0 (int64_t arg3);
[HOOKS] Called int sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);
[HOOKS] Called entry.init0 ();
[HOOKS] Called entry.init1 ();
[HOOKS] Called char *sym.imp.getenv (const char *name);
[HOOKS] Called long sym.imp.ptrace (__ptrace_request request, pid_t pid, void*addr, void*data);
[HOOKS] Called int main (int argc, char **argv, char **envp);
[HOOKS] Called int sym.imp.printf (const char *format);
[HOOKS] Called char *sym.imp.fgets (char *s, int size, FILE *stream);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[DEBUG] Found 1 solutions
[0x00400844]> 
```

As you can see, there is a lot more debugging information printed during exploration because these hooks have been installed. These hooks are useful for tracking what angr is doing during an exploration.

## Hooking loops

Loops famously pose a challenge for symbolic execution due to the problem of path explosion. The `Mhl` command hooks the start of a loop and prints debugging information each iteration to make debugging these kinds of issues simpler.

```
[0x00400610]> Mhl
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-06-15 16:34:02,911 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffff with 8 unconstrained bytes referenced from 0x400615 (PLT.ptrace+0x15 in r100 (0x400615))
[HOOKS] Found 4 loops
[0x00400610]> Meu main
[DEBUG] Starting exploration. Find: [0x4007e8]
[HOOKS] Starting loop at 0x4008d0
[HOOKS]  [1|0] {Loop count: 1} Looping at 0x4008d0 
[HOOKS] Starting loop at 0x4007e4
[HOOKS]  [3|0] {Loop count: 1} Looping at 0x4007e4 
[HOOKS]  [3|0] {Loop count: 2} Looping at 0x4007e4 
[HOOKS]  [3|0] {Loop count: 3} Looping at 0x4007e4 
[HOOKS]  [3|0] {Loop count: 4} Looping at 0x4007e4 
[HOOKS]  [3|0] {Loop count: 5} Looping at 0x4007e4 
[DEBUG] Found 1 solutions
```
