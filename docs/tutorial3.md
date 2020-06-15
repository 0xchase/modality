# Finding Output

For this challenge we'll be exploring until a state has a certain string in stdin. The binary is 02_angr_find_condition. We'll start by opening the binary and running some basic analysis.

```
shell@shell:~/github/r2angr/docs/challenges$ r2 02_angr_find_condition 
 -- Check your IO plugins with 'r2 -L'
[0x08048450]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x08048450]> s main
[0x080485c8]> 
```

The CFG for the main function is, once again, very large, so I recommend you avoid graph mode. We can see from scrolling through the function in visual mode that again it gets user input from stdin, calls `sym.complex_function`, and then there is a large branching structure with various success/fail prints. Without investigating much futher, we already know we want it to print "Good Job.", so let's try exploring until we find that. First though, let's add hooks to all functions that print a debug statement so we can trace what's happening during exploration. We can add the hooks as shown below.

```
[0x08048778]> Mhf
[R2ANGR] Importing angr
[R2ANGR] Loading r2angr
[R2ANGR] Initialized r2angr at entry point
[HOOKS] Hooking function: entry0 at 0x8048450
[HOOKS] Hooking import: sym.imp.__libc_start_main at 0x8048420
[HOOKS] Hooking function: sym.deregister_tm_clones at 0x8048490
[HOOKS] Hooking function: sym.register_tm_clones at 0x80484c0
[HOOKS] Hooking function: sym.__do_global_dtors_aux at 0x8048500
[HOOKS] Hooking function: entry.init0 at 0x8048520
[HOOKS] Hooking function: sym.__libc_csu_fini at 0x804d2f0
[HOOKS] Hooking function: sym.__x86.get_pc_thunk.bx at 0x8048480
[HOOKS] Hooking function: sym.complex_function at 0x8048569
[HOOKS] Hooking function: sym._fini at 0x804d2f4
[HOOKS] Hooking function: sym.__libc_csu_init at 0x804d290
[HOOKS] Hooking function: main at 0x80485c8
[HOOKS] Hooking function: sym.print_msg at 0x804854b
[HOOKS] Hooking import: sym.imp.printf at 0x80483e0
[HOOKS] Hooking function: sym._init at 0x8048394
[HOOKS] Hooking import: sym.imp.strcmp at 0x80483d0
[HOOKS] Hooking import: sym.imp.__stack_chk_fail at 0x80483f0
[HOOKS] Hooking import: sym.imp.puts at 0x8048400
[HOOKS] Hooking import: sym.imp.exit at 0x8048410
[HOOKS] Hooking import: sym.imp.__isoc99_scanf at 0x8048430
[0x08048450]> 
```

Then we can explore until a state has "Good Job" in stdout as shown below.

```
[0x08048450]> Meo Good Job
[DEBUG] Starting exploration. Find: [Good Job]
[HOOKS] Called entry0 ();
[HOOKS] Called int sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);
[HOOKS] Called sym.__libc_csu_init (int32_t arg_4h, int32_t arg_8h);
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-06-15 17:42:39,342 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x804d291 (__libc_csu_init+0x1 in 02_angr_find_condition (0x804d291))
WARNING | 2020-06-15 17:42:39,344 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x804d293 (__libc_csu_init+0x3 in 02_angr_find_condition (0x804d293))
[HOOKS] Called sym.__x86.get_pc_thunk.bx ();
[HOOKS] Called sym._init ();
[HOOKS] Called sym.__x86.get_pc_thunk.bx ();
[HOOKS] Called entry.init0 ();
[HOOKS] Called sym.register_tm_clones ();
[HOOKS] Called int main (int argc, char **argv, char **envp);
[HOOKS] Called sym.print_msg ();
[HOOKS] Called int sym.imp.printf (const char *format);
WARNING | 2020-06-15 17:42:39,838 | angr.state_plugins.symbolic_memory | Filling memory at 0x804f040 with 240 unconstrained bytes referenced from 0x90512d0 (printf+0x0 in libc.so.6 (0x512d0))
[HOOKS] Called int sym.imp.printf (const char *format);
[HOOKS] Called int sym.imp.__isoc99_scanf (const char *format);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called sym.complex_function (int32_t arg_8h, int32_t arg_ch);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called void sym.imp.exit (int status);
[HOOKS] Called int sym.imp.strcmp (const char *s1, const char *s2);
WARNING | 2020-06-15 17:42:41,897 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffefffc with 72 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
WARNING | 2020-06-15 17:42:41,898 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff70 with 4 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
WARNING | 2020-06-15 17:42:41,898 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff4d with 11 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
WARNING | 2020-06-15 17:42:41,910 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fff0044 with 20 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
[HOOKS] Called int sym.imp.puts (const char *s);
[HOOKS] Called int sym.imp.puts (const char *s);
[DEBUG] Found 1 solutions
[0x080495d8]> 
```

Our hooks give us some idea of what was happening during this exploration. We can then list the remaining states with the `Msl` command.

```
[0x080495d8]> Msl
Active states:
  0 0x804d26c
  1 0x80495d8

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

We have two active states, let's see what is in stdout for each one using the `Mso` command.

```
[0x080495d8]> Mso
Active state 0 at 0x804d26c:
placeholder
Enter the password: Try again.

Active state 1 at 0x80495d8:
placeholder
Enter the password: Good Job.

[0x080495d8]> 
```

Looks like the first one failed, we'll kill it with the `Msk` command.

```
[0x080495d8]> Msk 0
[0x080495d8]> 
```

Now we'll list the stdin for the final state as shown below.

```
[0x080495d8]> Msi
Active state 0 at 0x80495d8:
UFOHHURD
[0x080495d8]> 
```

Let's try this password on the binary.

```
[0x080495d8]> q
chase@chase:~/github/r2angr/docs/challenges$ ./02_angr_find_condition 
placeholder
Enter the password: UFOHHURD
Good Job.
chase@chase:~/github/r2angr/docs/challenges$ 
```
