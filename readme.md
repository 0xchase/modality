# r2angr

This project is in it's early stages and will only work on some binaries.

# Todo

## Ideas
Integrate ghidra with the disassembler
implement callFunction - gives args necessary to return specific value
Use inspect.b with call to print calls/other info in a tree
When state splits, print [1|2] => [1|3] with split address
Use inspect.b with simprocedure to update this information
Print function return values if in CONFIG
Deal with offets for PIE
Create log for each state. On hooks, add information to state "log" string

Change printing format to have [DEBUG] [PRINT] [HOOK] etc
Detect path explosion
If path explosion detected, do one more loop to check where split occurs, print that instruction and address

## Priority
 - Watchpoints
 - Analysis commands for loops, functions, etc
 - If enabled, replace commands like `dr` with symbolic information

## Bugs
 - State revive/save doesn't work

---

## Debugger
 - Add avoid/find annotation commands
 - Add find stages commands
 - der command broken
 - PEDA like view for debugging. Commands to print regs and stack
 - Single line states printing for loop exploring
 - Add logging events throughout, command to print this information. Can annotate graph with log.
 - Debug function, finding args for specific return value
 - Switch between concrete and symbolic execution
 - Detailed register/stack printing information for specific state
 - Improve watchpoint print message

## Hooks
 - When hooking function calls, print args
 - When hit calls like strlen(), choose to simulate or constrain
 - Automatically hook unknown windows functions. Print and skip, or lookup return type and symbolize.
 - Detect path explosion
 - If path explosion detected, while in loop, print instruction/address where split to identify cause

## State
 - Track/log history for each state
 - Can highlight state execution history
 - Add command to print detailed info about state at current address. Can be used with visual panels mode.

## Other
 - Get working as scripting engine
 - Easy way to edit script inside radare2 (initialize using this script if `mis` is run)
 - Add commands to seek between different states
 - Get custom visual panels mode working

# Research Ideas
 - Generate models of malware system call dependecies, recover higher level functionality. Ex: On branch 1, do write to file and print, on branch 2, print and read from input, connet to server. Etc.
 - Switch between concrete and symbolic execution. Use this to bypass packer. Using Symbion exloration method, example on angr blog.
