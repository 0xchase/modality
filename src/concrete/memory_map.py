class MemoryMap:
    """
    Describing a memory range inside the concrete
    process.
    """
    def __init__(self, start_address, end_address, offset, name):
        self.start_address = start_address
        self.end_address = end_address
        self.offset = offset
        self.name = name

    def __str__(self):
        my_str = "MemoryMap[start_address: 0x%x | end_address: 0x%x | name: %s" \
              % (self.start_address,
                 self.end_address,
                 self.name)

        return my_str
