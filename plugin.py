#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
r2angr
"""

import r2lang
import r2pipe
import sys

r = r2pipe.open()

session = None
initialized = False

def r2angr(_):
    global session
    global initialized

    """Build the plugin"""

    binary = r.cmdj("ij")["core"]["file"]

    def process(command):
        global session
        global initialized

        """Process commands here"""

        if not command.startswith("m"):
            return 0

        if not initialized:
            sys.path.append("src/")
            try:
                from r2angr import R2ANGR
                session = R2ANGR(binary, r)
                initialized = True
            except Exception as e:
                print(e)
        try:
            session.run(command[1:])
        except Exception as e:
            print(e)

        try:
            return session.return_value
        except:
            return 1

    return {"name": "r2-angr",
            "licence": "GPLv3",
            "desc": "Integrates angr with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2angr):
    print("An error occurred while registering r2angr")

