import logging
import os
from base64 import b64encode, b64decode

from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError, SimConcreteBreakpointError

from angr_targets.concrete import ConcreteTarget

l = logging.getLogger("angr_targets.r2")
l.setLevel(logging.DEBUG)


class R2ConcreteTarget(ConcreteTarget):
   
    def __init__(self, r2):
        self.r2 = r2
        super(R2ConcreteTarget, self).__init__()

        print("Initialized R2ConcreteTarget")

    def exit(self):
        self.r2.quit()

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target
            :param int address: The address to read from
            :param int nbytes:  The amount number of bytes to read
            :return:        The memory read
            :rtype: str
            :raise angr.errors.SimMemoryError
        """

        print("Reading R2ConcreteTarget memory")

        l.debug("R2ConcreteTarget read_memory at %x "%(address))

        # Check if it's mapped
        if self.r2.cmd('dm.@{}'.format(hex(address))) == '':
            error = "R2ConcreteTarget can't read_memory at address {address}. Page is not mapped.".format(address=hex(address))
            l.error(error)
            raise SimConcreteMemoryError(error)

        return bytes(self.r2.cmdj('pxj {} @ {}'.format(nbytes, hex(address))))


    def write_memory(self,address, value, **kwargs):
        """
        Writing to memory of the target
            :param int address:   The address from where the memory-write should start
            :param bytes value:     The actual value written to memory
            :raise angr.errors.ConcreteMemoryError
        """

        print("Writing R2ConcreteTarget memory")

        assert type(value) is bytes, 'write_memory value is actually type {}'.format(type(value))

        l.debug("R2ConcreteTarget write_memory at %x value %s " %(address, value))

        try:
            self.r2.cmd("w6d {} @ {}".format(b64encode(value).decode(), hex(address)))
            """
            if not res:
                l.warning("R2ConcreteTarget failed write_memory at %x value %s"%(address,value))
                raise SimConcreteMemoryError("R2ConcreteTarget failed write_memory to address %x" % (address))
            """
        except Exception as e:
            l.warning("R2ConcreteTarget write_memory at %x value %s exception %s"%(address,value,e))
            raise SimConcreteMemoryError("R2ConcreteTarget write_memory at %x value %s exception %s" % (address, str(value), e))

   
    def read_register(self,register,**kwargs):
        """"
        Reads a register from the target
            :param str register: The name of the register
            :return: int value of the register content
            :rtype int
            :raise angr.errors.ConcreteRegisterError in case the register doesn't exist or any other exception
        """

        print("Reading R2ConcreteTarget register")

        # Resolve some regs
        if register in ['pc','sp','bp']:
            l.debug('R2ConcreteTarget resolving %s',register)
            register = self.r2.cmd('drn {}'.format(register)).strip()
            l.debug('R2ConcreteTarget resolved to %s', register)

        try:
            l.debug("R2ConcreteTarget read_register at %s "%(register))
            registers = self.r2.cmdj('drtj all')
        except Exception as e:
            l.debug("R2ConcreteTarget read_register %s exception %s %s "%(register,type(e).__name__,e))
            raise SimConcreteRegisterError("R2ConcreteTarget can't read register %s exception %s" % (register, e))

        if register in registers:
            return registers[register]

        # XMM
        if register.startswith('xmm'):
            try:
                return (registers[register + 'l'] << 64) + registers[register + 'h']
            except KeyError:
                # This can be somewhat expected... xmm<n> wasn't found
                l.warn('{} was not found.'.format(register))
                pass

        # R2 Currently also has a bug with floating point registers being shown incorrectly: https://github.com/radare/radare2/issues/13118

        error = 'Unhandled register read of {}'.format(register)
        l.error(error)
        raise SimConcreteRegisterError(error)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
            :param str register:     The name of the register
            :param int value:        int value written to be written register
            :raise angr.errors.ConcreteRegisterError
        """

        print("Writing R2ConcreteTarget register")

        # XMM/ST writes fail atm: https://github.com/radare/radare2/issues/13090
        # Resolve some regs
        if register in ['pc','sp','bp']:
            l.debug('R2ConcreteTarget resolving %s',register)
            register = self.r2.cmd('drn {}'.format(register)).strip()
            l.debug('R2ConcreteTarget resolved to %s', register)

        registers = self.r2.cmdj('drtj all')

        #TODO: Implement xmm writes

        if register not in registers:
            error = "R2ConcreteTarget write_register unhandled reg name of {}".format(register)
            l.error(error)
            raise SimConcreteRegisterError(error)

        l.debug("R2ConcreteTarget write_register at %s value %x "%(register,value))
        self.r2.cmd('dr {}={}'.format(register, value))

        # Validate write
        if self.read_register(register) != value:
            error = "R2ConcreteTarget write_register failed to correctly set register {}={}".format(register, hex(value))
            l.error(error)
            raise SimConcreteRegisterError(error)


    def set_breakpoint(self,address, **kwargs):
        """Inserts a breakpoint
                :param optional bool hardware: Hardware breakpoint
                :param optional bool temporary:  Tempory breakpoint
                :param optional str regex:     If set, inserts breakpoints matching the regex
                :param optional str condition: If set, inserts a breakpoint with the condition
                :param optional int ignore_count: Amount of times the bp should be ignored
                :param optional int thread:    Thread cno in which this breakpoints should be added
                :raise angr.errors.ConcreteBreakpointError
        """

        if kwargs != {}:
            l.warn('R2ConcreteTarget set_breakpoint called with extra args "{}". Currently, R2 is not handling these and will set breakpoint as normal software breakpoint.'.format(kwargs))

        l.debug("R2ConcreteTarget set_breakpoint at %x "%(address))
        self.r2.cmd('db {}'.format(hex(address)))

        # Sanity check that breakpoint actually got set
        if not any(x for x in self.r2.cmdj('dbj') if x['addr'] == address):
            raise SimConcreteBreakpointError("R2ConcreteTarget failed to set_breakpoint at %x" % (address))

    def remove_breakpoint(self, address, **kwargs):
        l.debug("R2ConcreteTarget remove_breakpoint at %x "%(address))
        self.r2.cmd('db-{}'.format(hex(address)))

        # Sanity check that breakpoint got removed
        if any(x for x in self.r2.cmdj('dbj') if x['addr'] == address):        
            raise SimConcreteBreakpointError("R2ConcreteTarget failed to remove_breakpoint at %x" % (address))

    def set_watchpoint(self,address, **kwargs):
        """Inserts a watchpoint
                :param address: The name of a variable or an address to watch
                :param optional bool write:    Write watchpoint
                :param optional bool read:     Read watchpoint
                :raise angr.errors.ConcreteBreakpointError
        """

        read = kwargs.pop('read', False)
        write = kwargs.pop('write', False)

        rw_str = ''
        if read:
            rw_str += 'r'
        if write:
            rw_str += 'w'

        if rw_str == '':
            error = 'R2ConcreteTarget set_watchpoint invalid watch requested for address {}. Must specify type of watchpoint.'.format(hex(address))
            l.error(error)
            raise SimConcreteBreakpointError(error)

        if kwargs != {}:
            l.warn('R2ConcreteTarget set_watchpoint called with extra args "{}".'.format(kwargs))

        l.debug("R2ConcreteTarget target set_watchpoing at %x value"%(address))
        self.r2.cmd('dbw {address} {fmt}'.format(address=address, fmt=rw_str))

        # Make sure it got set
        if not any(x for x in self.r2.cmdj('dbj') if x['addr'] == address and x['hw'] == True):
            raise SimConcreteBreakpointError("R2ConcreteTarget failed to set_breakpoint at %x" % (address))

    def remove_watchpoint(self,address, **kwargs):
        """Removes a watchpoint
                :param address: The name of a variable or an address to watch
                :raise angr.errors.ConcreteBreakpointError
        """

        if kwargs != {}:
            l.warn('R2ConcreteTarget set_watchpoint called with extra args "{}".'.format(kwargs))

        # R2 treats watch points the same as hw breakpoints. Just passthing this call through.
        self.remove_breakpoint(address)


    def get_mappings(self):
        """Returns the mmap of the concrete process
        :return:
        """

        l.debug("getting the vmmap of the concrete process")
        sections = self.r2.cmdj('dmj')
        files = self.r2.cmdj('dmmj')

        vmmap = []

        for section in sections:

            map_start_address = section['addr']
            map_end_address = section['addr_end']

            try:
                file_map = next(x for x in files if x['file'] == section['file'])
                offset = map_start_address - file_map['addr']

            except:
                offset = 0

            map_name = section['file']
            vmmap.append(MemoryMap(map_start_address, map_end_address, offset, map_name))

        return vmmap

    def is_running(self):
        # This implementation is synchronous. We will not be running if this call is being made.
        return False

    def stop(self):
        # This implementation is synchronous. We will not be running if this call is being made.
        return

    def run(self):
        """
        Resume the execution of the target
        :return:
        """

        l.debug('R2ConcreteTarget run')
        self.r2.cmd('dc')

    @property
    def architecture(self):
        return self.r2.cmdj('iAj')['bins'][0]['arch']

    @property
    def bits(self):
        return self.r2.cmdj('iAj')['bins'][0]['bits']


from angr_targets.memory_map import MemoryMap
