# 6502 pcode emulation script (designed for C64 6510 demonstrations)
#
# github c64cryptoboy/c64_ghidra, Jan '23
#
# Found these x86 examples useful when writing this script:
#    blog: https://saml98.github.io/jekyll/update/2022/05/23/ghidra-stack-strings-emulation.html
#       with code: https://github.com/SamL98/GhidraStackStrings/blob/master/emulator_utils.py
#    code: https://gist.github.com/blundeln/fccbae3b3dcc113d17715d933ea34c02 
#
#
# Notes:

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

VERBOSE = True

class PcodeEmu6502(object):
    STACK_BOTTOM = 0x1ff
    STACK_TOP = 0x100  # grows backwards
    
    # Defined in https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/6502/data/languages/6502.slaspec
    #    'A', 'X', 'Y', 'PC', 'SP', 'N', 'V', 'B', 'D', 'I', 'Z', 'C'
    # PC and SP little endian, but can get as individual bytes using 'PCL', 'PCH', 'S' and 'SH'  
    # 'B' flag is fiction (no memory on chip), can only exist on stack
    #
    #  Note: according to https://www.masswerk.at/6502/6502_instruction_set.html
    #      "The status register (SR) is also known as the P register."
    #      6502.slaspec has a "P" register: "define register offset=0x00  size=1 [ A X Y P ];""
    #      But it is unused (not a flags byte), so maybe "P" stands for padding instead?   
    SLEIGH_REG_AND_FLAG_NAMES = ['A', 'X', 'Y', 'PCL', 'PCH', 'S', 'N', 'V', 'D', 'I', 'Z', 'C']

    def __init__(self):
        self.emu = EmulatorHelper(currentProgram)
        self.mem = currentProgram.getMemory()
        self.step_num = 0
        self.emu.enableMemoryWriteTracking(True)

    def get_pc(self):
        return self.emu.readRegister('PC') # or readRegister(self.emu.getPCRegister())

    def set_pc(self, val):
        if isinstance(val, ghidra.program.model.address.Address):
            val = val.getOffset()
        self.emu.writeRegister('PC', val)

    def get_16bit_sp(self):
        return self.emu.readRegister('SP') # or readRegister(self.emu.getStackPointerRegister())

    def get_sp(self):
        return self.emu.readRegister('S')

    def set_16bit_sp(self, val):
        if isinstance(val, ghidra.program.model.address.Address):
            val = val.offset
        self.emu.writeRegister('SP', val)

    def read(self, addr, size):
        return bytearray(self.emu.readMemory(addr, size))

    # for an addr containing a valid instruction, move the PC to the start of the following instruction
    # returns updated PC
    def move_pc_to_next_inst(self, addr):
        inst = getInstructionAt(addr)
        print("Skipping $%s: %s" % (str(addr), str(inst)))
        next_instruction = inst.getNext()  # like pc.add(inst.length)
        next_addr = next_instruction.getAddress()
        self.set_pc(next_addr)
        return next_addr  

    def block_containing_addr(self, addr):
        for block in self.mem.getBlocks():
            if block.getStart() <= addr <= block.getEnd():
                return block
        return None

    def emulate(self, start_addr_int, update_memory, max_steps, end_addr_int, tolerate_mods_to_dataflow):
        self.set_pc(start_addr_int)
        self.set_16bit_sp(self.STACK_BOTTOM)
        self.step_num = 0

        while True:
            if VERBOSE:
                regs_flags = {}
                for name in self.SLEIGH_REG_AND_FLAG_NAMES:
                    regs_flags[name] = self.emu.readRegister(name)
                
                pc_str = '%04x' % (regs_flags['PCH'] * 256 + regs_flags['PCL'])
                a_str = '%02x' % (regs_flags['A'])
                x_str = '%02x' % (regs_flags['X'])
                y_str = '%02x' % (regs_flags['Y'])   
                sp_str = '%02x' % (regs_flags['S'])
                flags_byte = (regs_flags['N'] * 128 + regs_flags['V'] * 64 + regs_flags['D'] * 8 + regs_flags['I'] * 4
                         + regs_flags['Z'] * 2 + regs_flags['C']) # 6502 has no 'B' flag reg on die
                flags_str = "{0:08b}".format(flags_byte)

                print("%d PC:%s A:%s X:%s Y:%s SP:%s NV-BDIZC:%s" % (self.step_num, pc_str, a_str, x_str, y_str, sp_str, flags_str))

            # stop on user abort
            if monitor.isCancelled():
                print("stopped: user canceled script")
                return
         
            # stop if PC fell outside of defined memory (RTS popping a weird stack addr, etc.)
            pc = toAddr(self.get_pc())
            if pc.isNonLoadedMemoryAddress():
                print("stopped: PC (%s) fell outside of defined memory" % hex(pc.getOffset()))
                return

            # End if stack underflows (presumably from a final RTS or RTI)
            # (The 6502 8-bit SP register wraps, however, Ghidra provides a 16-bit stack pointer,
            # making it easy to know if we've over/underflowed the stack.
            # So less of a bug than a feature? :)
            if self.get_16bit_sp() > self.STACK_BOTTOM:
                print("done: instruction popped from an empty stack")
                return

            # end if emulation reaches specified ending address
            if end_addr_int is not None and pc.getOffset() == end_addr_int:
                print("done: ending address reached")
                return
            
            # end if emulation reaches specified (or default) max steps
            if max_steps is not None and self.step_num >= max_steps:
                print("done: maximum steps reached")
                return

            # stop if no instruction found
            inst = getInstructionAt(pc)
            if inst is None:
                disassemble(pc) # Start disassembling at the specified address.
                inst = getInstructionAt(pc)
                if inst is None:
                    print("error: no instruction found at PC")
                    return

            self.step_num += 1  

            # skip JSRs and JMPs that flow outside of defined memory
            if not tolerate_mods_to_dataflow:
                # Note: tolerate_mods_to_dataflow is here because asking Ghidra for reference info
                #       is, for some reason, unsafe if the code had modified memory that program Counter
                #       dataflow will then pass through.  At varying times, it will "SystemExit"
                #       in the console and exit from the script with no explaination in the log.            
                references = getReferencesFrom(pc)
                if len(references) > 0:
                    if len(references) > 1:
                        exit("Assumption bug: I assume this shouldn't happen in 6502 land?")
                    ref = references[0]
                    # I assume I don't need to check isComputed() for an indirect JMP?
                    if ref.referenceType.isCall() or ref.referenceType.isJump():
                        print("DEBUG: %s" % ref.referenceType)
                        dest = ref.getToAddress()

                        # I tried "if not dest.isLoadedMemoryAddress()", but that didn't work as
                        # expected, so doing this check manually:                    
                        if self.block_containing_addr(dest) is None:
                            pc = self.move_pc_to_next_inst(pc)
                            continue

            if VERBOSE:
                print("processing %s\n" % inst)
            success = self.emu.step(monitor)
            if not success:
                print("error: emulation issue: %s" % self.emu.getLastError())
                break

            if update_memory:
                set_of_writes = self.emu.getTrackedMemoryWriteSet()  # a set of addr ranges
                
                # Ignore address ranges that have a space of "unique" (pcode plumbing) or "register"
                filtered = [x for x in set_of_writes if x.getAddressSpace().getName() not in ('unique', 'register')]

                if len(filtered) > 0:
                    addr_to_write = filtered[0].getMinAddress()

                    # sanity check
                    if (len(filtered) > 1 or addr_to_write != filtered[0].getMaxAddress()):
                        print("error: expected a 6502 instruction to update at most one memory location")

                    if addr_to_write is not None:
                        new_value = self.emu.readMemoryByte(addr_to_write)
                        try:
                            self.mem.setByte(addr_to_write, new_value)
                        except ghidra.program.model.mem.MemoryAccessException:
                            clearListing(addr_to_write) # Clears the code unit (instruction or data) defined at the address.
                            self.mem.setByte(addr_to_write, new_value)

                        # This approach keeps the changes to the emulator memory in sync with the program
                        # memory on each step.  Could probably wait until emulator is done, and then just
                        # dump memory changes back into program, as things like self-modifying code
                        # to branches are evaluated based on the emulator's memory.
                        self.emu.enableMemoryWriteTracking(False) # clear the accumulated list of memory writes after step
                        self.emu.enableMemoryWriteTracking(True) # start recording again
        # end of while
    

    def run(self, start_addr, update_memory = True, max_steps = 2000, end_addr = None, tolerate_mods_to_dataflow = False):
        try:
            self.emulate(start_addr, update_memory, max_steps, end_addr, tolerate_mods_to_dataflow)
        finally:
            max_steps_str = ''
            if max_steps is not None:
                max_steps_str = 'of %d ' % max_steps
            print("performed %d %ssteps" % (self.step_num, max_steps_str))
            if self.emu is not None:
                self.emu.dispose()
            

def run():
    # TODO: Should get user input for params, just hard coded for now
    start_addr = 0xc000
    end_addr = None
    max_steps = None
    update_memory = True
    tolerate_mods_to_dataflow = False

    PcodeEmu6502().run(start_addr, update_memory, max_steps, end_addr, tolerate_mods_to_dataflow)

run()
