# Initialization

Modality automatically initializes a state at the entry point when the plugin is loaded. However, under some circumstances it is useful to reinitialize this state or initialize it at a different location, which is the purpose of the commands under this classification.

The avaliable commands can be listed as shown below.

```
[0x08048687]> Mi?
Getting help
| Mi[?]                 Initialize at entry point
| Mie                   Initialize at entry point
| Mib                   Initialize blank state at current address
```

## Initializing at entry0

The `Mie` command will initialize the simgr at the entry point detected by radare2.

```
[0x08048687]> Mie
[R2ANGR] Initialized r2angr at entry point
```

## Blank states

Blank states can be initialized at the current address using the `Mib` command. 

```
[0x08048450]> Mib
WARNING | 2020-06-15 16:11:42,459 | angr.sim_state | Unused keyword arguments passed to SimState: args
[R2ANGR] Initialized r2angr blank state at current address
[0x08048450]> 
```

They can also be combined with the radare2 `@` symbol to initialize at any other address or function name, as shown below.

```
[0x08048450]> Mib @ main
WARNING | 2020-06-15 16:13:04,559 | angr.sim_state | Unused keyword arguments passed to SimState: args
[R2ANGR] Initialized r2angr blank state
[0x08048450]> 
```
