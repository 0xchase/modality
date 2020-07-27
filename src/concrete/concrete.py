import logging
l = logging.getLogger("angr_targets.concrete")
#l.setLevel(logging.DEBUG)

class ConcreteTarget(object):
    """
    Concrete target used inside the SimConcreteEngine.
    This object is defined in the angr script.
    """
    def __init__(self):
        self.timeout = None
        return

    def read_memory(self, address,nbytes, **kwargs):
        """
        Reading from memory of the target
        :param int address: The address to read from
        :param int nbytes:  The amount number of bytes to read
        :return:        The memory read
        :rtype: bytes
        :raise angr.errors.ConcreteMemoryError:
        """
        raise NotImplementedError()

    def write_memory(self, address, value, **kwargs):
        """
        Writing to memory of the target
        :param int address:   The address from where the memory-write should start
        :param str value:     The actual value written to memory
        :raise angr.errors.ConcreteMemoryError:
        """
        raise NotImplementedError()

    def read_register(self, register, **kwargs):
        """"
        Reads a register from the target
        :param str register: The name of the register
        :return: int value of the register content
        :rtype int
        :raise angr.errors.ConcreteRegisterError: in case the register doesn't exist or any other exception
        """
        raise NotImplementedError()

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
        :param str register:     The name of the register
        :param int value:        int value written to be written register
        :raise angr.errors.ConcreteRegisterError:
        """
        raise NotImplementedError()

    def set_breakpoint(self, address, **kwargs):
        """
        Inserts a breakpoint
        :param int address: The address at which to set the breakpoint
        :param optional bool hardware: Hardware breakpoint
        :param optional bool temporary:  Tempory breakpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        raise NotImplementedError()

    def remove_breakpoint(self, address, **kwargs):
        raise NotImplementedError()

    def set_watchpoint(self, address, **kwargs):
        """
        Inserts a watchpoint
        :param address: The name of a variable or an address to watch
        :param optional bool write:    Write watchpoint
        :param optional bool read:     Read watchpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        raise NotImplementedError()

    def remove_watchpoint(self, address, **kwargs):
        raise NotImplementedError()

    def get_mappings(self):
        raise NotImplementedError()

    def run(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def execute_shellcode(self, shellcode, result_register):
        """
        Use the methods provided by the ConcreteTarget to inject shellcode in concrete process and get the result of the shellcode in the "result_register" register
        :param concrete_target: ConcreteTarget where the shellcode will be injected
        :param shellcode: shellcode to be executed
        :param result_register: register which will contain the result
        :return: value contained in the result_register
        Example read fs[0] value on x64
            shellcode = "\x64\x48\x8B\x04\x25\x00\x00\x00\x00"    # mov rax, fs:[0]
            result_register = "rax"
            execute_shellcode(target, shellcode, result_register)
        """
        # FIXME: registers could be clobbered during shellcode execution, we should save
        # registers before shellcode and then restore them.

        l.debug("Execute shellcode method!")

        len_payload = len(shellcode)

        l.debug("encoded shellcode  %s len shellcode %s" % (str(shellcode), len_payload))

        pc = self.read_register("pc")
        l.debug("current pc %x" % (pc))

        # save the content of the current instruction
        old_instr_content = self.read_memory(pc, len_payload)

        l.debug("current instruction %s" % (str(old_instr_content)))

        # saving value of the register which will be used to read segment register
        old_reg_value = self.read_register(result_register)
        l.debug("exfiltration reg %s value %x" % (result_register, old_reg_value))

        # writing to pc shellcode
        self.write_memory(pc, shellcode)

        cur_instr_after_write = self.read_memory(pc, len_payload)
        l.debug("current instruction after write %s" % (str(cur_instr_after_write)))

        l.debug('setting breakpoint at address %#x' % (pc+len_payload))

        self.set_breakpoint(pc + len_payload, temporary=True)
        self.run()

        current_pc = self.read_register("pc")
        l.debug("current pc %x" % (current_pc))

        result_value = self.read_register(result_register)
        l.debug("result value %x " % (result_value))

        # restoring previous pc
        self.write_register("pc", pc)

        current_pc = self.read_register("pc")
        l.debug("current pc %x" % (current_pc))


        # restoring previous instruction
        self.write_memory(pc, old_instr_content)

        # restoring previous rax value
        self.write_register(result_register, old_reg_value)

        pc = self.read_register("pc")
        eax_value = self.read_register(result_register)
        instr_content = self.read_memory(pc, len_payload)
        l.debug("pc %x eax value %x instr content %s " % (pc, eax_value, str(instr_content)))

        return result_value
