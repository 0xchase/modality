#!/usr/bin/python2

import subprocess
import struct
import os
from one_gadget import generate_one_gadget

for offset in generate_one_gadget("/lib/x86_64-linux-gnu/libc.so.6"):
    print(hex(offset))
