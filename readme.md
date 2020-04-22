# Modality Debugger

This project is in it's early stages and will only work on some binaries. In progress docs can be found [here](https://github.com/chase1635321/Modality/wiki).

Modality is a debugger built on the popular symbolic execution engine Angr. It provides an interface (inspired by radare2) for a reverse engineer to perform symbolic executino, constraint solving, emulation, etc without writing scripts. One complete, this tool should be efficient at solving most CTF reversing challenges. 

## Example

Here's an example of using the tool to solve the lockpicksim challenge from umdctf 2017. First we'll open the binary with the tool as shown below.
```
chase@chase:~/github/Modality$ ./tool.py challenges/lockpicksim 
Imported libraries
['challenges/lockpicksim']
WARNING | 2020-03-28 20:55:40,900 | claripy.ast.bv | BVV value is being coerced from a unicode string, encoding as utf-8
```
Next we'll explore until the main function using the `deu` command (debug explore until <address|symbol>). This uses Angr's explore method.
```
[0x400600|0]> deu main
Debug explore until 0x4006f6
Found 1 solutions
```
As we can see the tool found 1 path to get to that function. Next we'll continue until a branch (state split), using the `dcb` command (debug continue branch).
```
[0x4006f6|0]> dcb
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-03-28 20:55:48,477 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 56 unconstrained bytes referenced from 0x109dc70 (strlen+0x0 in libc.so.6 (0x9dc70))
WARNING | 2020-03-28 20:55:48,478 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff60 with 8 unconstrained bytes referenced from 0x109dc70 (strlen+0x0 in libc.so.6 (0x9dc70))
```
We can print the dissassembly for each state at this branch using the `pd` command (print dissassembly). We can see that the first state corresponds to a sucess condition and the second one corresponds to a failure.
```
[0x4008a0 0x4008ca|0]> pd
-----------------------------------------------------------  -----------------------------
cmp dword [var_2ch], 1                                       mov edi, str.Wrong
jne 0x4008ca                                                 call sym.imp.puts
lea rax, [var_20h]                                           mov eax, 1
mov rdi, rax                                                 mov rsi, qword [var_8h]
call sym.imp.atoi                                            xor rsi, qword fs:[0x28]
mov esi, eax                                                 je 0x4008ed
mov edi, str.Correct__Flag:_UMDCTF__you_p1cked__d_correctly  call sym.imp.__stack_chk_fail
mov eax, 0                                                   leave
call sym.imp.printf                                          ret
mov eax, 0                                                   nop
-----------------------------------------------------------  -----------------------------
```
Because we don't want the second state, we'll kill it with the `sk` command (state kill <state number>). 
```
[0x4008a0 0x4008ca|0]> sk 1
[0x4008a0|1]> pi
+4863
[0x4008a0|1]> ds
Single step
[0x4008a6 0x4008ca|1]> pi
4801
```
We are now on the correct branch, we can continue to output using the `dco` command (debug continue output).
```
[0x4008a0|1]> dco
		        _____   
		       / ___ \     
		      / /   \ \    
		     / /     \ \ 
		     | |     | |
		     | |     | |
		     | |     | |
		---------------------
		|     Lock Pick     |
		|     SIMULATOR     |
		|                   |
		|                   |
		| Can you pick this |
		|   4-pin virtual   |
		|       lock?       |
		---------------------

		Password: 
	Correct! Flag: UMDCTF-{you_p1cked_4801_correctly}


[0x4008c3 0x4000050|1]>
```
This gives us the flag for the challenge. Doing this manually would require either manually reversing a buch of xor's and shifts, or brute forcing.
