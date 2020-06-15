# Exploration

Modality contains a number of exploration commands. These can be listed with the `Me?` command.

```
[0x08048450]> Me?
Getting help
| Me[?]                 Explore using find/avoid comments
| Meu <addr>            Explore until address
| Meo <string>          Explore until string is in stdout
```

Currently there are only three options, but eventually all of the angr exploration methods and some variations will be included.

## Exploring to a location

The simplest command to use is probably the `Meu <addr|function>` command. This command explores until a state reaches a specified address or function name. An example of exploring to the main address is shown below. 

```
[0x08048450]> Meu main
[DEBUG] Starting exploration. Find: [0x80485c7]
WARNING | 2020-06-15 15:22:15,566 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80486b1 (__libc_csu_init+0x1 in 00_angr_find (0x80486b1))
WARNING | 2020-06-15 15:22:15,568 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80486b3 (__libc_csu_init+0x3 in 00_angr_find (0x80486b3))
[DEBUG] Found 1 solutions
[0x080485c7]> 
```

## Exploring using find/avoid comments

The `Me` command explores using the addresses marked by the radare2 comments "find" or "avoid". An example is shown below.

```
[0x08048450]> CC+find @ main
[0x08048450]> Me
[DEBUG] Starting exploration.
Find: [0x80485c7]. Avoid: [].
WARNING | 2020-06-15 15:28:03,910 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80486b1 (__libc_csu_init+0x1 in 00_angr_find (0x80486b1))
WARNING | 2020-06-15 15:28:03,912 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80486b3 (__libc_csu_init+0x3 in 00_angr_find (0x80486b3))
[DEBUG] Found 1 solutions
[0x080485c7]> 
```

The `CC+` command adds a comment at that address, and the `Me` command is used to explore to it. Most of the time you'll use find/avoid addresses because you want to set multiple throughout the binary. It's often convienient to add these comments by pressing `;` in the graph view.

## Exploring using stdout

The `Meo` command explores until a state has a specified value in stdout. This is useful, for example, if you want to find the input for some CTF challenge that gets the binary to print "Sucess". 

```
[0x080485c7]> Meo Good Job
[DEBUG] Starting exploration. Find: [Good Job]
WARNING | 2020-06-15 15:31:48,211 | angr.state_plugins.symbolic_memory | Filling memory at 0x804a040 with 240 unconstrained bytes referenced from 0x90512d0 (printf+0x0 in libc.so.6 (0x512d0))
WARNING | 2020-06-15 15:31:49,370 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffefffc with 103 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
WARNING | 2020-06-15 15:31:49,371 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff70 with 4 unconstrained bytes referenced from 0x907e300 (strcmp+0x0 in libc.so.6 (0x7e300))
[DEBUG] Found 1 solutions
[0x08048687]> 
```
