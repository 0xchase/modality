import angr, angrop

p = angr.Project("vuln")

rop = p.analyses.ROP()
rop.find_gadgets()
