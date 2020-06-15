# States

The states commands are used for manipulating and reading data from the various simulation manager stashes. The relevant commands can be listed as shown below.

```
[0x08048450]> Ms?
Getting help
| Ms[?]                 States list
| Msl <index>           List states
| Msi                   Print state stdin
| Mso                   Print state stdout
| Msk[?] <index|addr>   Kill state by index or address
| Msr[?] <index|addr>   Revive state by index or address
| Mss[?] <index|addr>   
| Mse <index|addr>      Extract single state and kill all others
```

## Listing states

States can be listed with the `Msl` command. 

```
[0x00400844]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4
  2 0x4005a0
  3 0x40085f
  4 0x40087f
  5 0x4000050
  6 0x400844

Deadended states:
  0 0x4000050
  1 0x4000050
  2 0x4000050
  3 0x4000050
  4 0x4000050
  5 0x4000050
  6 0x4000050
  7 0x4000050

[0x00400844]> 

```

States may be in either the *active* or *deadended* stashes. 

## Manipulating states

To optimize the exploration process it is useful to be able to kill in unwanted parts of the CFG. Some commands relevant to this include `Msk` (for killing states), `Msr` (for reviving states), `Mse` (for extracting states, or killing all states except for one), `Mska` (kill all states), and `Msra` revive all states. These commands can be used with indexes or addresses.

Here is an example of killing a state.

```
[0x004007e8]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4
  2 0x4007e8

[0x004007e8]> Msk 2
[0x004007e4]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4

Deadended states:
  0 0x4007e8

[0x004007e4]> 
```

Reviving a state.

```
[0x004007e4]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4

Deadended states:
  0 0x4007e8

[0x004007e4]> Msr 0x4007e8
[0x004007e8]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4
  2 0x4007e8
```

Extracting a state (this is the state command I use the most often).

```
[0x004007e8]> Msl
Active states:
  0 0x4007e4
  1 0x4007e4
  2 0x4007e8

[0x004007e8]> Mse 2
[0x004007e8]> Msl
Active states:
  0 0x4007e8

Deadended states:
  0 0x4007e4
  1 0x4007e4
```

Reviving all states

```
[0x004007e8]> Msl
Active states:
  0 0x4007e8

Deadended states:
  0 0x4007e4
  1 0x4007e4

[0x004007e8]> Msra
[0x004007e4]> Msl
Active states:
  0 0x4007e8
  1 0x4007e4
  2 0x4007e4
```

Killing all states.

```
[0x004007e4]> Msl
Active states:
  0 0x4007e8
  1 0x4007e4
  2 0x4007e4

[0x004007e4]> Mska
[0x004007e4]> Msl
Deadended states:
  0 0x4007e8
  1 0x4007e4
  2 0x4007e4
```

## Standard in/out

After exploring to some address, it may be useful to print the stdin/stdout for any state. This can be done using the `Msi` and `Mso` commands. An example of printing the input is below.

```
[0x00400844]> Msi
Active state 0 at 0x400844:
b'Code_Talkers\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
[0x00400844]> 
```

And printing the output

```
[0x0040084e]> Mso
Active state 0 at 0x40084e:
Enter the password: Nice!

[0x0040084e]> 
```
