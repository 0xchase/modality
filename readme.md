# r2angr

This project is in it's early stages and will only work on some binaries.

---

## Todo

### Priority
 - Major analysis commands
 - New printing format
 - Misc easy to implement commands
 - Get basic scripting working
 - Get installation working
 - Wiki and tutorial
 - Visual mode auto refresh
 - Short tool overview
 - Long tutorial video
 - Bug fixes, make commands more robust

---

### Emulation
 - [x] Basic initialization: `mi`
 - [ ] Initialize at arbitrary memory location
 - [ ] Initialize on function with current debugger args, specific args, or symbolic args
 - [x] Basic emulation: `mc`, `mcs`, `mcb`, `mcu`, `mco`
 - [x] Basic exploration: `me`, `meu`
 - [ ] Explore for certain output
 - [ ] Implement staged exploration
 - [ ] Add avoid/find annotation commands
 - [x] Basic watchpoint commands: `mw`, `mwl`
 - [ ] More watchpoint commands (remove watchpoints, run command at watchpoints)
 - [ ] Switch between concrete and symbolic execution

### Analysis
 - [ ] Analysis commands for loops, functions, etc
 - [ ] Move analysis commands to the hook clasification

### Stash manipulation
 - [x] Basic state manipulation: `ms`, `msl`, `msk`, `msr`, `mse`, `mss`
 - [x] Group state operations: `mska`, `msra`
 - [ ] Kill/revive based on output
 - [ ] State seeking by index
 - [ ] States outputs and inputs
 - [ ] Print more detailed state information (current function, ...)

### Symbolize commands
 - [ ] Commands to symbolize registers or stack values with different data types
 - [ ] Commands to symbolize variables

### Visualization
 - [ ] Finalize found/active highlighting and stashing
 - [ ] Indent all printing according to call/loop hierarchy
 - [ ] Implement custom radare2 panels view for exploration
 - [ ] Print log of a state history
 - [ ] If enabled, replace commands like `dr` with symbolic information
 - [ ] Graph an emulation history, with branches at state splitting and annotations for loops, branches, etc
 - [ ] Standardize print messages with formats like [DEBUG] [PRINT] [HOOK] etc
 - [ ] Command to print detailed info about state at current address. Can be used with visual panels mode.
 - [ ] Annotate graph with state split locations

### Exploitation
 - [ ] Figure out features

### Hooks
 - [ ] When hooking function calls, print args
 - [ ] Print function return values
 - [ ] Command to add hooks at locations, run some r2 command there
 - [ ] When state splits, print [1|2] => [1|3] with split address
 - [ ] Add custom hooks for strlen, etc that ask for length or arbitrary length. Can also set this in the config.

### Other
 - [ ] Deal with offets for PIE
 - [ ] Commands to edit config.txt file
 - [ ] Integrate ghidra with the disassembler
 - [ ] Watchpoint comment hit count doesn't work
 - [ ] Watchpoint hits should work per state
 - [ ] Remove watchpoints unimplemented
 - [ ] der command broken
 - [ ] Tools for dealing with path explosion
 - [ ] Get working as scripting engine
 - [ ] Easy way to edit script inside radare2 that runs at the beginning. Can add custom hooks this way.
 - [ ] Make commands robust, go through and check for bugs
 - [ ] Write wiki for this project. Write tutorial for this project

