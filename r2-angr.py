#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
r2-angr
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

        if command == "mi":
            sys.path.append("src/")
            try:
                from session import Session
                session = Session(binary, r)
                initialized = True
            except Exception as e:
                print(e)
        else:
            try:
                if initialized:
                    session.run(command[1:])
                else:
                    print("r2angr not initialized")
            except Exception as e:
                print(e)

        # Parse arguments
        #tmp = command.split(" ")
        #print(str(tmp))
        return 1

    return {"name": "r2-angr",
            "licence": "GPLv3",
            "desc": "Integrates angr with radare2",
            "call": process}

# Register the plugin
if not r2lang.plugin("core", r2angr):
    print("An error occurred while registering r2angr")

