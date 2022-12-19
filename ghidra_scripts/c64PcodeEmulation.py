# 6502 pcode emulation script (designed for C64 6510 demonstrations)
#
# github c64cryptoboy/c64_ghidra, Dec '22
#
# Found these examples useful when writing this script:
#    blog: https://gist.github.com/blundeln/fccbae3b3dcc113d17715d933ea34c02 
#       with code: https://github.com/SamL98/GhidraStackStrings/blob/master/emulator_utils.py
#    blog: https://saml98.github.io/jekyll/update/2022/05/23/ghidra-stack-strings-emulation.html
#       with code: https://github.com/SamL98/GhidraStackStrings/blob/master/emulator_utils.py
#
# Class based on Ghidra's EmulationHelper:
#    https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling
#       /src/main/java/ghidra/app/emulator/EmulatorHelper.java

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

# Config
VERBOSE = True
UPDATE_MEMORY = False

class PcodeEmu6502(object):
    STACK_BOTTOM = 0x1ff
    STACK_TOP = 0x100  # grows backwards
    # Defined in https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/6502/data/languages/6502.slaspec
    #    'A', 'X', 'Y', 'PC', 'SP', 'N', 'V', 'B', 'D', 'I', 'Z', 'C'
    # PC and SP little endian, but can get as individual bytes using 'PCL', 'PCH', 'S' and 'SH'  
    # 'B' flag is fiction (no memory on chip), can only exist on stack
    SLEIGH_REG_AND_FLAG_NAMES = ['A', 'X', 'Y', 'PCL', 'PCH', 'S', 'N', 'V', 'D', 'I', 'Z', 'C']

    def __init__(self):
        self.emu = EmulatorHelper(currentProgram)
        if UPDATE_MEMORY:
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

    def move_pc_to_next_inst(self, addr):
        instruction = currentProgram.getListing().getInstructionAt(addr)
        print("Skipping $%s: %s" % (str(addr), str(instruction)))
        next_instruction = instruction.getNext()
        self.set_pc(next_instruction.getAddress())
        return next_instruction
        # todo: other approach
        # new_pc = pc.add(insn.length)
        # self.set_pc(new_pc)      

    def emulate(self, start_addr_int, max_steps, end_addr_int):
        self.set_pc(start_addr_int)
        self.set_16bit_sp(self.STACK_BOTTOM)
        step_num = 0
        while True:
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
            if self.get_16bit_sp() > self.STACK_BOTTOM:
                print("done: popped form empty stack")
                return

            # end if emulation reaches specified ending address
            if end_addr_int is not None and pc.getOffset() == end_addr_int:
                print("done: ending address reached")
                return
            
            # end if emulation reaches specified (or default) max steps
            if max_steps is not None and step_num >= max_steps:
                print("done: maximum steps reached")
                return

            # stop if no instruction found
            inst = getInstructionAt(pc)
            if inst is None:
                print("error: no instruction found at PC")
                return

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
                         + regs_flags['Z'] * 2 + regs_flags['C']) # 6502 has no die space for 'B' flag
                flags_str = "{0:08b}".format(flags_byte)

                print("PC:%s A:%s X:%s Y:%s SP:%s NV-BDIZC:%s" % (pc_str, a_str, x_str, y_str, sp_str, flags_str))
                # print("DEBUG: Stack: %d" % (self.get_16bit_sp()))

            step_num += 1  

            # skip JSRs and JMPs that flow outside of defined memory
            # TODO: Consider branches?
            references = getReferencesFrom(pc)
            if len(references) > 0:
                if len(references) > 1:
                    exit("TODO: BUG: I assume this shouldn't happen in 6502 land?")
                ref = references[0]
                # I assume I don't need to check isComputed() for an indirect JMP?
                if ref.referenceType.isCall() or ref.referenceType.isJump():
                    print("DEBUG: %s" % ref.referenceType)
                    dest = ref.getToAddress()

                    # TODO: BUG? When address is not in a defined block, this still returns false
                    #       could iterate over defined blocks and check if inside one...
                    if dest.isNonLoadedMemoryAddress():
                        self.move_pc_to_next_inst(pc)
                        pc = toAddr(self.emu.get_pc())
                        continue
            '''
            if inst.flowType.isCall() or inst.flowType.isJump 
                and
            '''

            print("DEBUG: processing %s" % inst)
            success = self.emu.step(monitor) # TODO: other example used (TaskMonitor.DUMMY)
            if not success:
                print("error: emulation issue: %s" % self.emu.getLastError())
                break

            if UPDATE_MEMORY:
                setOfMemoryWrites = self.emu.getTrackedMemoryWriteSet()
                addr_with_modded_val = setOfMemoryWrites.getMinAddress() # 6502 only changes up to a single address at a time
                if addr_with_modded_val is not None:
                    memory = currentProgram.getMemory()
                    new_value = self.emu.readMemoryByte(addr_with_modded_val)
                    # TODO: Do need to get an addr from the program's address space before doing this? Probably...
                    memory.setByte(addr_with_modded_val, new_value)
                    self.emu.enableMemoryWriteTracking(False) # clear the accumulated list of memory writes
                    self.emu.enableMemoryWriteTracking(True) # start recording again
        
        # end of while
      
            
    def run(self, start_addr, max_steps = 1000, end_addr = None):
        try:
            self.emulate(start_addr, max_steps, end_addr)
        finally:
            if self.emu is not None:
                self.emu.dispose()

def run():
    # TODO: Get user input for params, hard coded for now
    start_addr = 0x02a8
    end_addr = 0x02b3
    max_steps = 7

    PcodeEmu6502().run(start_addr, max_steps, end_addr)

run()    
