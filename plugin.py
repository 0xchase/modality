#! /usr/bin/env python3
# Copyright (C) 2017 Chase Kanipe

"""
modality
"""

import r2lang
import r2pipe
import sys

r = r2pipe.open()

session = None
initialized = False

def modality(_):
    global session
    global initialized


    def process(command):
        global session
        global initialized

        if not command.startswith("M"):
            return 0

        binary = r.cmd("i~file").split("\n")[0].split(" ")[-1]

        if not initialized:
            sys.path.append("src/")
            try:
                from r2angr import R2ANGR
                session = R2ANGR(binary, r)
                initialized = True

                session.load_angr()

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

if not r2lang.plugin("core", modality):
    print("An error occurred while registering modality")
