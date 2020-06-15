# Emulation

Most of the time you'll want to use the exploration commands instead of the emulation ones, but a few emulation commands are included so angr can be used like a debugger. Most of these are variations of the `Mc` (continue) command. The commands can be listed as shown below.

```
[0x08048687]> Mc?
Getting help
| Mc[?]                 Continue emulation
| Mcs <addr>            Continue emulation one step
| Mcu <addr>            Continue emulation until address
| Mcb                   Continue emulation until branch
| Mco                   Continue emulation until output
[0x08048687]> 
```

## Continuing

The `Mc` command will continue emulation until all states have deadended.

```
[0x08048687]> Mc
[DEBUG] Continuing emulation
[0x08048687]> Msl
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
  16 0xc000048
  17 0xc000048
```

As you can see, continuing and then listing the states leaves us with 17 deadended states.

## Stepping

The `Ms` command can be use to step all the states.

```
[0x08048687]> Mcs
[DEBUG] Continuing emulation one step
```

## Continuing to address

The `Mcu` command can be used to continue emulation until a state hits the specified address or function.

```
[0x08048687]> Mcu main
[DEBUG] Continuing emulation until main
```

## Continuing to branch

The `Mcb` command can be used to continue emulation until a state hits a branch (where the state will split).

```
[0x08048687]> Mcb
[DEBUG] Continuing emulation until branch
```
