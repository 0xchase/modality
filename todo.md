# Todo

## Immediatley
 - Move exploit.py into modality code
 - Integrate R2ConcreteTarget()
 - Deal with PIC

## General
 - Interactive exploration mode: steps until state increase, user chooses left or right
 - Many hooks for standard functions like scanf, print arguments in nice format
 - On shellcode buffer, attempt to constraint each byte to \x41

## Vulnerability Detection
 - Explore for unconstrained state
 - Explore for unconstrained value in call to system()
 - Detect format strings
 - Hook strcpy, check length of buffer, iterate over stack looking for unconstrained values, check if there's overlap
 - Detect use-after-free, double-free: https://github.com/angr/angr/issues/478

### Testing
 - Test on the Juliet test cases (118 different CWE, 64,099 test cases). https://samate.nist.gov/SRD/testsuite.php
 - Test on OpenSSL-1.1.0f, libpng-1.5.20, and tiff-3.8.1 (from VYPER paper)
 - Test on Zeratool challenges

## Exploitation
 - Exploit buffer overflows
 - Exploit format strings
 - Integrate with angrop
 - Integrate with pwntools
 - Fancy shellcode printer
   - Prints shellcode in a colored way labelling the length of each section
 - Solve every exploit-exercises challenge in < 15 seconds. Show video of this solving. Show video of solving previous r2con challenges.


## Other
 - state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
 - Fancy shellcode printing format like "\x41"*80 + {shellcode} + "\x42"*8 (pc overwrite)
