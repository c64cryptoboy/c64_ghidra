from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol.SourceType import USER_DEFINED, IMPORTED

ADDRESS   = 0x00002000  # Bit set if the operand is used as an address (otherwise assume scalar).

# options enum
ADDR_LABEL   = 0
ADDR_COMMENT = 1
ROMKERNAL    = 100
RAMKERNAL    = 101
ROMBASIC     = 102
RAMBASIC     = 103
IOREGS       = 104
ROMANDIO1541 = 105
RAM1541      = 106

# from http://unusedino.de/ec64/technical/project64/memory_maps.html
romkernal_labels = {
    57344 : ("", "e000:EXP continued From BASIC ROM"),
    57411 : ("polyx", "e043:Series Evaluation"),
    57485 : ("rmulc", "e08d:Constants for RND"),
    57495 : ("rnd", "e097:Perform [rnd]"),
    57593 : ("bioerr", "e0f9:Handle I/O Error in BASIC"),
    57612 : ("bchout", "e10c:Output Character"),
    57618 : ("bchin", "e112:Input Character"),
    57624 : ("bckout", "e118:Set Up For Output"),
    57630 : ("bckin", "e11e:Set Up For Input"),
    57636 : ("bgetin", "e124:Get One Character"),
    57642 : ("sys", "e12a:Perform [sys]"),
    57686 : ("savet", "e156:Perform [save]"),
    57701 : ("verfyt", "e165:Perform [verify / load]"),
    57790 : ("opent", "e1be:Perform [open]"),
    57799 : ("closet", "e1c7:Perform [close]"),
    57812 : ("slpara", "e1d4:Get Parameters For LOAD/SAVE"),
    57856 : ("combyt", "e200:Get Next One Byte Parameter"),
    57862 : ("deflt", "e206:Check Default Parameters"),
    57870 : ("cmmerr", "e20e:Check For Comma"),
    57881 : ("ocpara", "e219:Get Parameters For OPEN/CLOSE"),
    57956 : ("cos", "e264:Perform [cos]"),
    57963 : ("sin", "e26b:Perform [sin]"),
    58036 : ("tan", "e2b4:Perform [tan]"),
    58126 : ("atn", "e30e:Perform [atn]"),
    58235 : ("bassft", "e37b:BASIC Warm Start [RUNSTOP-RESTORE]"),
    58260 : ("init", "e394:BASIC Cold Start"),
    58274 : ("initat", "e3a2:CHRGET For Zero-page"),
    58303 : ("initcz", "e3bf:Initialize BASIC RAM"),
    58402 : ("initms", "e422:Output Power-Up Message"),
    58439 : ("bvtrs", "e447:Table of BASIC Vectors (for 0300)"),
    58451 : ("initv", "e453:Initialize Vectors"),
    58463 : ("words", "e45f:Power-Up Message"),
    58541 : ("", "e4ad:Patch for BASIC Call to CHKOUT"),
    58586 : ("", "e4da:Reset Character Colour"),
    58592 : ("", "e4e0:Pause After Finding Tape File"),
    58604 : ("", "e4ec:RS-232 Timing Table -- PAL"),
    58624 : ("iobase", "e500:Get I/O Address"),
    58629 : ("screen", "e505:Get Screen Size"),
    58634 : ("plot", "e50a:Put / Get Row And Column"),
    58648 : ("cint1", "e518:Initialize I/O"),
    58692 : ("", "e544:Clear Screen"),
    58726 : ("", "e566:Home Cursor"),
    58732 : ("", "e56c:Set Screen Pointers"),
    58778 : ("", "e59a:Set I/O Defaults (Unused Entry)"),
    58784 : ("", "e5a0:Set I/O Defaults"),
    58804 : ("lp2", "e5b4:Get Character From Keyboard Buffer"),
    58826 : ("", "e5ca:Input From Keyboard"),
    58930 : ("", "e632:Input From Screen or Keyboard"),
    59012 : ("", "e684:Quotes Test"),
    59025 : ("", "e691:Set Up Screen Print"),
    59062 : ("", "e6b6:Advance Cursor"),
    59117 : ("", "e6ed:Retreat Cursor"),
    59137 : ("", "e701:Back on to Previous Line"),
    59158 : ("", "e716:Output to Screen"),
    59178 : ("", "e72a:-unshifted characters-"),
    59348 : ("", "e7d4:-shifted characters-"),
    59516 : ("", "e87c:Go to Next Line"),
    59537 : ("", "e891:Output <CR>"),
    59553 : ("", "e8a1:Check Line Decrement"),
    59571 : ("", "e8b3:Check Line Increment"),
    59595 : ("", "e8cb:Set Colour Code"),
    59610 : ("", "e8da:Colour Code Table"),
    59626 : ("", "e8ea:Scroll Screen"),
    59749 : ("", "e965:Open A Space On The Screen"),
    59848 : ("", "e9c8:Move A Screen Line"),
    59872 : ("", "e9e0:Syncronise Colour Transfer"),
    59888 : ("", "e9f0:Set Start of Line"),
    59903 : ("", "e9ff:Clear Screen Line"),
    59923 : ("", "ea13:Print To Screen"),
    59940 : ("", "ea24:Syncronise Colour Pointer"),
    59953 : ("", "ea31:Main IRQ Entry Point"),
    60039 : ("scnkey", "ea87:Scan Keyboard"),
    60125 : ("", "eadd:Process Key Image"),
    60281 : ("", "eb79:Pointers to Keyboard decoding tables"),
    60484 : ("", "ec44:Graphics/Text Control"),
    60647 : ("", "ece7:Shift-Run Equivalent"),
    60656 : ("", "ecf0:Low Byte Screen Line Addresses"),
    60681 : ("talk", "ed09:Send TALK Command on Serial Bus"),
    60684 : ("listn", "ed0c:Send LISTEN Command on Serial Bus"),
    60736 : ("", "ed40:Send Data On Serial Bus"),
    60845 : ("", "edad:Flag Errors"),
    60845 : ("", "edad:Status #80 - device not present"),
    60848 : ("", "edb0:Status #03 - write timeout"),
    60857 : ("second", "edb9:Send LISTEN Secondary Address"),
    60862 : ("", "edbe:Clear ATN"),
    60871 : ("tksa", "edc7:Send TALK Secondary Address"),
    60876 : ("", "edcc:Wait For Clock"),
    60893 : ("ciout", "eddd:Send Serial Deferred"),
    60911 : ("untlk", "edef:Send UNTALK / UNLISTEN"),
    60947 : ("acptr", "ee13:Receive From Serial Bus"),
    61061 : ("", "ee85:Serial Clock On"),
    61070 : ("", "ee8e:Serial Clock Off"),
    61079 : ("", "ee97:Serial Output 1"),
    61088 : ("", "eea0:Serial Output 0"),
    61097 : ("", "eea9:Get Serial Data And Clock In"),
    61107 : ("", "eeb3:Delay 1 ms"),
    61115 : ("", "eebb:RS-232 Send"),
    61190 : ("", "ef06:Send New RS-232 Byte"),
    61230 : ("", "ef2e:'No DSR' / 'No CTS' Error"),
    61241 : ("", "ef39:Disable Timer"),
    61258 : ("", "ef4a:Compute Bit Count"),
    61273 : ("", "ef59:RS-232 Receive"),
    61310 : ("", "ef7e:Set Up To Receive"),
    61328 : ("", "ef90:Process RS-232 Byte"),
    61409 : ("", "efe1:Submit to RS-232"),
    61453 : ("", "f00d:No DSR (Data Set Ready) Error"),
    61463 : ("", "f017:Send to RS-232 Buffer"),
    61517 : ("", "f04d:Input From RS-232"),
    61574 : ("", "f086:Get From RS-232"),
    61604 : ("", "f0a4:Serial Bus Idle"),
    61629 : ("", "f0bd:Table of Kernal I/O Messages"),
    61739 : ("", "f12b:Print Message if Direct"),
    61743 : ("", "f12f:Print Message"),
    61758 : ("getin", "f13e:Get a byte"),
    61783 : ("chrin", "f157:Input a byte"),
    61849 : ("", "f199:Get From Tape / Serial / RS-232"),
    61898 : ("chrout", "f1ca:Output One Character"),
    61966 : ("chkin", "f20e:Set Input Device"),
    62032 : ("chkout", "f250:Set Output Device"),
    62097 : ("close", "f291:Close File"),
    62223 : ("", "f30f:Find File"),
    62239 : ("", "f31f:Set File values"),
    62255 : ("clall", "f32f:Abort All Files"),
    62259 : ("clrchn", "f333:Restore Default I/O"),
    62282 : ("open", "f34a:Open File"),
    62421 : ("", "f3d5:Send Secondary Address"),
    62473 : ("", "f409:Open RS-232"),
    62622 : ("load", "f49e:Load RAM"),
    62648 : ("", "f4b8:Load File From Serial Bus"),
    62771 : ("", "f533:Load File From Tape"),
    62927 : ("", 'f5af:Print "SEARCHING"'),
    62913 : ("", "f5c1:Print Filename"),
    62930 : ("", 'f5d2:Print "LOADING / VERIFYING"'),
    62941 : ("save", "f5dd:Save RAM"),
    62970 : ("", "f5fa:Save to Serial Bus"),
    63065 : ("", "f659:Save to Tape"),
    63119 : ("", 'f68f:Print "SAVING"'),
    63131 : ("udtim", "f69b:Bump Clock"),
    63197 : ("rdtim", "f6dd:Get Time"),
    63204 : ("settim", "f6e4:Set Time"),
    63213 : ("stop", "f6ed:Check STOP Key"),
    63227 : ("", "f6fb:Output I/O Error Messages"),
    63227 : ("", "f6fb:'too many files'"),
    63230 : ("", "f6fe:'file open'"),
    63233 : ("", "f701:'file not open'"),
    63236 : ("", "f704:'file not found'"),
    63239 : ("", "f707:'device not present'"),
    63242 : ("", "f70a:'not input file'"),
    63245 : ("", "f70d:'not output file'"),
    63248 : ("", "f710:'missing filename'"),
    63251 : ("", "f713:'illegal device number'"),
    63277 : ("", "f72d:Find Any Tape Header"),
    63338 : ("", "f76a:Write Tape Header"),
    63440 : ("", "f7d0:Get Buffer Address"),
    63447 : ("", "f7d7:Set Buffer Stat / End Pointers"),
    63466 : ("", "f7ea:Find Specific Tape Header"),
    63501 : ("", "f80d:Bump Tape Pointer"),
    63511 : ("", 'f817:Print "PRESS PLAY ON TAPE"'),
    63534 : ("", "f82e:Check Tape Status"),
    63544 : ("", 'f838:Print "PRESS RECORD..."'),
    63553 : ("", "f841:Initiate Tape Read"),
    63588 : ("", "f864:Initiate Tape Write"),
    63605 : ("", "f875:Common Tape Code"),
    63696 : ("", "f8d0:Check Tape Stop"),
    63714 : ("", "f8e2:Set Read Timing"),
    63788 : ("", "f92c:Read Tape Bits"),
    64096 : ("", "fa60:Store Tape Characters"),
    64398 : ("", "fb8e:Reset Tape Pointer"),
    64407 : ("", "fb97:New Character Setup"),
    64422 : ("", "fba6:Send Tone to Tape"),
    64456 : ("", "fbc8:Write Data to Tape"),
    64461 : ("", "fbcd:IRQ Entry Point"),
    64599 : ("", "fc57:Write Tape Leader"),
    64659 : ("", "fc93:Restore Normal IRQ"),
    64696 : ("", "fcb8:Set IRQ Vector"),
    64714 : ("", "fcca:Kill Tape Motor"),
    64721 : ("", "fcd1:Check Read / Write Pointer"),
    64731 : ("", "fcdb:Bump Read / Write Pointer"),
    64738 : ("", "fce2:Power-Up RESET Entry"),
    64770 : ("", "fd02:Check For 8-ROM"),
    64786 : ("", "fd12:8-ROM Mask '80CBM'"),
    64789 : ("restor", "fd15:Restore Kernal Vectors (at 0314)"),
    64794 : ("vector", "fd1a:Change Vectors For User"),
    64816 : ("", "fd30:Kernal Reset Vectors"),
    64848 : ("ramtas", "fd50:Initialise System Constants"),
    64923 : ("", "fd9b:IRQ Vectors For Tape I/O"),
    64931 : ("ioinit", "fda3:Initialise I/O"),
    64989 : ("", "fddd:Enable Timer"),
    65017 : ("setnam", "fdf9:Set Filename"),
    65024 : ("setlfs", "fe00:Set Logical File Parameters"),
    65031 : ("readst", "fe07:Get I/O Status Word"),
    65048 : ("setmsg", "fe18:Control OS Messages"),
    65057 : ("settmo", "fe21:Set IEEE Timeout"),
    65061 : ("memtop", "fe25:Read / Set Top of Memory"),
    65076 : ("membot", "fe34:Read / Set Bottom of Memory"),
    65091 : ("", "fe43:NMI Transfer Entry"),
    65126 : ("", "fe66:Warm Start Basic [BRK]"),
    65212 : ("", "febc:Exit Interrupt"),
    65218 : ("", "fec2:RS-232 Timing Table - NTSC"),
    65238 : ("", "fed6:NMI RS-232 In"),
    65287 : ("", "ff07:NMI RS-232 Out"),
    65347 : ("", "ff43:Fake IRQ Entry"),
    65352 : ("", "ff48:IRQ Entry"),
    65371 : ("cint", "ff5b:Initialize screen editor"),
    65408 : ("", "ff80:Kernal Version Number [03]"),
    65409 : ("cint", "ff81:Init Editor & Video Chips"),
    65412 : ("ioinit", "ff84:Init I/O Devices  Ports & Timers"),
    65415 : ("ramtas", "ff87:Init Ram & Buffers"),
    65418 : ("restor", "ff8a:Restore Vectors"),
    65421 : ("vector", "ff8d:Change Vectors For User"),
    65424 : ("setmsg", "ff90:Control OS Messages"),
    65427 : ("secnd", "ff93:Send SA After Listen"),
    65430 : ("tksa", "ff96:Send SA After Talk"),
    65433 : ("memtop", "ff99:Set/Read System RAM Top"),
    65436 : ("membot", "ff9c:Set/Read System RAM Bottom"),
    65439 : ("scnkey", "ff9f:Scan Keyboard"),
    65442 : ("settmo", "ffa2:Set Timeout In IEEE"),
    65445 : ("acptr", "ffa5:Handshake Serial Byte In"),
    65448 : ("ciout", "ffa8:Handshake Serial Byte Out"),
    65451 : ("untalk", "ffab:Command Serial Bus UNTALK"),
    65454 : ("unlsn", "ffae:Command Serial Bus UNLISTEN"),
    65457 : ("listn", "ffb1:Command Serial Bus LISTEN"),
    65460 : ("talk", "ffb4:Command Serial Bus TALK"),
    65463 : ("readss", "ffb7:Read I/O Status Word"),
    65466 : ("setlfs", "ffba:Set Logical File Parameters"),
    65469 : ("setnam", "ffbd:Set Filename"),
    65472 : ("(iopen)", "ffc0:Open Vector [f34a]"),
    65475 : ("(iclose)", "ffc3:Close Vector [f291]"),
    65478 : ("(ichkin)", "ffc6:Set Input [f20e]"),
    65481 : ("(ichkout)", "ffc9:Set Output [f250]"),
    65484 : ("(iclrch)", "ffcc:Restore I/O Vector [f333]"),
    65487 : ("(ichrin)", "ffcf:Input Vector chrin [f157]"),
    65490 : ("(ichrout)", "ffd2:Output Vector chrout [f1ca]"),
    65493 : ("load", "ffd5:Load RAM From Device"),
    65496 : ("save", "ffd8:Save RAM To Device"),
    65499 : ("settim", "ffdb:Set Real-Time Clock"),
    65502 : ("rdtim", "ffde:Read Real-Time Clock"),
    65505 : ("(istop)", "ffe1:Test-Stop Vector [f6ed]"),
    65508 : ("(igetin)", "ffe4:Get From Keyboad [f13e]"),
    65511 : ("(iclall)", "ffe7:Close All Channels And Files [f32f]"),
    65514 : ("udtim", "ffea:Increment Real-Time Clock"),
    65517 : ("screen", "ffed:Return Screen Organization"),
    65520 : ("plot", "fff0:Read / Set Cursor X/Y Position"),
    65523 : ("iobase", "fff3:Return I/O Base Address")
}

ramkernal_labels = {
    # TODO
}

rombasic_labels = {
    # TODO
}

rambasic_labels = {
    # TODO
}

# from http://unusedino.de/ec64/technical/project64/memory_maps.html
# and https://archive.org/details/Compute_s_Mapping_the_Commodore_64
ioregs_labels = {
    53249 : ("SPOY", "D001:Sprite 0 Y Pos"),
    53250 : ("SP1X", "D002:Sprite 1 X Pos"),
    53251 : ("SP1Y", "D003:Sprite 1 Y Pos"),
    53252 : ("SP2X", "D004:Sprite 2 X Pos"),
    53253 : ("SP2Y", "D005:Sprite 2 Y Pos"),
    53254 : ("SP3X", "D006:Sprite 3 X Pos"),
    53255 : ("SP3Y", "D007:Sprite 3 Y Pos"),
    53256 : ("SP4X", "D008:Sprite 4 X Pos"),
    53257 : ("SP4Y", "D009:Sprite 4 Y Pos"),
    53258 : ("SP5X", "D00A:Sprite 5 X Pos"),
    53259 : ("SP5Y", "D00B:Sprite 5 Y Pos"),
    53260 : ("SP6X", "D00C:Sprite 6 X Pos"),
    53261 : ("SP6Y", "D00D:Sprite 6 Y Pos"),
    53262 : ("SP7X", "D00E:Sprite 7 X Pos"),
    53263 : ("SP7Y", "D00F:Sprite 7 Y Pos"),
    53264 : ("MSIGX", "D010:Sprites 0-7 X Pos (msb of X coord.)"),
    53265 : ("SCROLY", "D011:VIC Control Register"),
    53266 : ("RASTER", "D012:Read Raster / Write Raster Value for Compare"),
    53267 : ("LPENX", "D013:Light-Pen Latch X Pos"),
    53268 : ("LPENY", "D014:Light-Pen Latch Y Pos"),
    53269 : ("SPENA", "D015:Sprite display Enable: 1 = Enable"),
    53270 : ("SCROLX", "D016:VIC Control Register"),
    53271 : ("YXPAND", "D017:Sprites O-7 Expand 2x Vertical (Y)"),
    53272 : ("VMCSB", "D018:VIC Memory Control Register"),
    53273 : ("VICIRQ", "D019:VIC Interrupt Flag Register"),
    53274 : ("IRQMSK", "D01A:IRQ Mask Register: 1 = Interrupt Enabled"),
    53275 : ("SPBGPR", "D01B:Sprite to Background Display Priority"),
    53276 : ("SPMC", "D01C:Sprites O-7 Multi-Color Mode Select"),
    53277 : ("XXPAND", "D01D:Sprites 0-7 Expand 2x Horizontal (X)"),
    53278 : ("SPSPCL", "D01E:Sprite to Sprite Collision Detect"),
    53279 : ("SPBGCL", "D01F:Sprite to Background Collision Detect"),
    53280 : ("EXTCOL", "D020:Border Color"),
    53281 : ("BGCOL0", "D021:Background Color 0"),
    53282 : ("BGCOL1", "D022:Background Color 1"),
    53283 : ("BGCOL2", "D023:Background Color 2"),
    53284 : ("BGCOL3", "D024:Background Color 3"),
    53285 : ("SPMC0", "D025:Sprite Multi-Color Register 0"),
    53286 : ("SPMC1", "D026:Sprite Multi-Color Register 1"),
    53287 : ("SP0CL", "D027:Sprite 0 Color"),
    53288 : ("SP1CL", "D028:Sprite 1 Color"),
    53289 : ("SP2CL", "D029:Sprite 2 Color"),
    53290 : ("SP3CL", "D02A:Sprite 3 Color"),
    53291 : ("SP4CL", "D02B:Sprite 4 Color"),
    53292 : ("SP5CL", "D02C:Sprite 5 Color"),
    53293 : ("SP6CL", "D02D:Sprite 6 Color"),
    53294 : ("SP7CL", "D02E:Sprite 7 Color"),
    54272 : ("FRELO1", "D400:Voice 1: Frequency Control - Low-Byte"),
    54273 : ("FREHI1", "D401:Voice 1: Frequency Control - High-Byte"),
    54274 : ("PWLO1", "D402:Voice 1: Pulse Waveform Width - Low-Byte"),
    54275 : ("PWHI1", "D403:Voice 1: Pulse Waveform Width - High-Nybble"),
    54276 : ("VCREG1", "D404:Voice 1: Control Register"),
    54277 : ("ATDCY1", "D405:Envelope Generator 1: Attack / Decay Cycle"),
    54278 : ("SUREL1", "D406:Envelope Generator 1: Sustain / Release Cycle"),
    54279 : ("FRELO2", "D407:Voice 2: Frequency Control - Low-Byte"),
    54280 : ("FREHI2", "D408:Voice 2: Frequency Control - High-Byte"),
    54281 : ("PWLO2", "D409:Voice 2: Pulse Waveform Width - Low-Byte"),
    54282 : ("PWHI2", "D40A:Pulse Waveform Width - High-Nybble"),
    54283 : ("VCREG2", "D40B:Voice 2: Control Register"),
    54284 : ("ATDCY2", "D40C:Envelope Generator 2: Attack / Decay Cycle"),
    54285 : ("SUREL2", "D40D:Envelope Generator 2: Sustain / Release Cycle Control"),
    54286 : ("FRELO3", "D40E:Voice 3: Frequency Control - Low-Byte"),
    54287 : ("FREHI3", "D40F:Voice 3: Frequency Control - High-Byte"),
    54288 : ("PWLO3", "D410:Voice 3: Pulse Waveform Width - Low-Byte"),
    54289 : ("PWHI3", "D411:Voice 3: Pulse Waveform Width - High-Nybble"),
    54290 : ("VCREG3", "D412:Voice 3: Control Register"),
    54291 : ("ATDCY3", "D413:Envelope Generator 3: Attack/Decay Cycle Control"),
    54285 : ("SUREL3", "D414:Envelope Generator 3: Sustain / Release Cycle Control"),
    54293 : ("CUTLO", "D415:Filter Cutoff Frequency: Low-Nybble"),
    54294 : ("CUTHI", "D416:Filter Cutoff Frequency: High-Byte"),
    54295 : ("RESON", "D417:Filter Resonance Control / Voice Input"),
    54296 : ("SIGVOL", "D418:Select Filter Mode and Volume"),
    54297 : ("POTX", "D419:Analog/Digital Converter: Game Paddle 1"),
    54298 : ("POTY", "D41A:Analog/Digital Converter Game Paddle 2"),
    54299 : ("RANDOM", "D41B:Oscillator 3 Random Number Generator"),
    54230 : ("ENV3", "D41C:Envelope Generator 3 Output"),
    55296 : ("", "D800:Start of Color RAM"),
    56320 : ("CIAPRA", "DC00:cia1: Data Port A (Keyboard, Joystick, Paddles, Light-Pen)"),
    56321 : ("CIAPRB", "DC01:cia1: Data Port B (Keyboard, Joysticks, Paddles)"),
    56322 : ("CIDDRA", "DC02:cia1: Data Direction Register - Port A (56320)"),
    56323 : ("CIDDRB", "DC03:cia1: Data Direction Register - Port B (56321)"),
    56324 : ("TIMALO", "DC04:cia1: Timer A: Low-Byte"),
    56325 : ("TIMAHI", "DC05:cia1: Timer A: High-Byte"),
    56326 : ("TIMBLO", "DC06:cia1: Timer B: Low-Byte"),
    56327 : ("TIMBHI", "DC07:cia1: Timer B: High-Byte"),
    56328 : ("TODTEN", "DC08:cia1: Time-of-Day Clock: 1/10 Seconds"),
    56329 : ("TODSEC", "DC09:cia1: Time-of-Day Clock: Seconds"),
    56330 : ("TODMIN", "DC0A:cia1: Time-of-Day Clock: Minutes"),
    56331 : ("TODHRS", "DC0B:cia1: Time-of-Day Clock: Hours + AM/PM Flag (Bit 7)"),
    56332 : ("CIASDR", "DC0C:cia1: Synchronous Serial I/O Data Buffer"),
    56333 : ("CIAICR", "DC0D:cia1: CIA Interrupt Control Register"),
    56334 : ("CIACRA", "DC0E:cia1: CIA Control Register A"),
    56335 : ("CIACRB", "DC0F:cia1: CIA Control Register B"),
    56576 : ("CI2PRA", "DD00:cia2: Data Port A (Serial Bus RS-232, VIC Memory Control)"),
    56577 : ("CI2PRB", "DD01:cia2: Data Port B (User Port, RS-232)"),
    56578 : ("C2DDRA", "DD02:cia2: Data Direction Register - Port A"),
    56579 : ("C2DDRB", "DD03:cia2: Data Direction Register - Port B"),
    56580 : ("TI2ALO", "DD04:cia2: Timer A: Low-Byte"),
    56581 : ("TI2AHI", "DD05:cia2: Timer A: High-Byte"),
    56582 : ("TI2BLO", "DD06:cia2: Timer B: Low-Byte"),
    56583 : ("TI2BHI", "DD07:cia2: Timer B: High-Byte"),
    56584 : ("TO2TEN", "DD08:cia2: Time-of-Day Clock: 1/10 Seconds"),
    56585 : ("TO2SEC", "DD09:cia2: Time-of-Day Clock: Seconds"),
    56586 : ("TO2MIN", "DD0A:cia2: Time-of-Day Clock: Minutes"),
    56587 : ("TO2HRS", "DD0B:cia2: Time-of-Day Clock: Hours + AM/PM Flag (Bit 7)"),
    56588 : ("CI2SDR", "DD0C:cia2: Synchronous Serial I/O Data Buffer"),
    56589 : ("CI2ICR", "DD0D:cia2: CIA Interrupt Control Register (Read"),
    56590 : ("CI2CRA", "DD0E:cia2: CIA Control Register A"),
    56591 : ("CI2CRB", "DD0F:cia2: CIA Control Register B")
}

# from https://ist.uwaterloo.ca/~schepers/MJK/ascii/1541map.txt
romio1541_labels = {
    # TODO
}

ram1541_labels = {
    # TODO
}

range_lookups = {
    ROMKERNAL: romkernal_labels, RAMKERNAL: ramkernal_labels, ROMBASIC: rombasic_labels, RAMBASIC: rambasic_labels,
    IOREGS: ioregs_labels, ROMANDIO1541: romio1541_labels, RAM1541: ram1541_labels
}


def run():
    memory = currentProgram.getMemory()
    symbol_table = currentProgram.getSymbolTable()
    
    # make sure something's selected
    if currentSelection is None or currentSelection.isEmpty():
        print("Error: Must select section to label")
        return

    choices = askChoices(
        "Labeling on addresses", "Select one or more ranges (recommend not mixing 1541 with others) and one or both actions", 
        [ROMKERNAL, RAMKERNAL, ROMBASIC, RAMBASIC, IOREGS, ROMANDIO1541, RAM1541, ADDR_LABEL, ADDR_COMMENT],
        ["Range: KERNAL ROM calls", "Range: KERNAL RAM usage", "Range: BASIC ROM calls", "Range: BASIC RAM usage",
         "Range: IO registers", "Range: 1541 IO and ROM calls", "Range: 1541 RAM usage", "Action: Address labels", "Action: Address comments"]
    )

    apply_labels = ADDR_LABEL in choices
    apply_commments = ADDR_COMMENT in choices     
    if not apply_labels and not apply_commments:   
        print "No action selected"
        return

    if apply_labels:
        choices.remove(ADDR_LABEL)
    if apply_commments:
        choices.remove(ADDR_COMMENT)
    lookups = {}
    for choice in choices:
        lookups.update(range_lookups[choice]) # merge all the selected ranges

    # https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/InstructionStub.html
    addr_iter = currentSelection.getAddresses(True) # True == iterate accending
    for addr in addr_iter:
        inst = getInstructionAt(addr)
        
        if inst is None:
            continue

        # toss single-byte instructions
        num_operands = inst.getNumOperands()
        if num_operands == 0:
            continue

        # instructions must reference a memory address
        operandType = inst.getOperandType(0)
        if operandType & ADDRESS == 0:
            continue

        # get the one or two-byte address in the operand (little endian)
        inst_bytes = inst.getBytes()
        operand_addr = inst_bytes[1] & 0xff
        if len(inst_bytes) == 3:
            operand_addr += (inst_bytes[2] & 0xff) * 256

        if operand_addr in lookups:
            lookup = lookups[operand_addr]

            if apply_labels:           
                symbol = symbol_table.getPrimarySymbol(addr)
                if symbol is None:
                    namespace = currentProgram.getGlobalNamespace()
                    new_symbol = symbol_table.createLabel(toAddr(operand_addr), lookup[0], namespace, USER_DEFINED)
                    new_symbol.setPrimary()
                    new_symbol.setPinned(True)

            if apply_commments:
                setEOLComment(addr, "%s" % (lookup[1]))

        # setEOLComment(addr, "%d %d %d %d" % (addr.getOffset(), len(inst.getBytes()), num_operands, operandType))


run()

'''
    # See https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/OperandType.java
  
	READ      = 0x00000001  # Bit set if operand refers to an address being read
	WRITE     = 0x00000002  # Bit set if operand refers to an address being written to
	INDIRECT  = 0x00000004  # Bit set if operand is an indirect reference
    IMMEDIATE = 0x00000008  # Bit set if operand is an immediate value.
    RELATIVE  = 0x00000010  # Bit set if operand depends on the instruction's address.
    IMPLICIT  = 0x00000020  # Bit set if operand is implicit.
    CODE      = 0x00000040  # Bit set it the address referred to contains code.
    DATA      = 0x00000080  # Bit set if the address referred to contains data.
    PORT      = 0x00000100  # Bit set if the operand is a port.
    REGISTER  = 0x00000200  # Bit set if the operand is a register.
    LIST      = 0x00000400  # Bit set if the operand is a list.
    FLAG      = 0x00000800  # Bit set if the operand is a flag.
    TEXT      = 0x00001000  # Bit set if the operand is text.
    ADDRESS   = 0x00002000  # Bit set if the operand is used as an address (otherwise assume scalar).
    SCALAR    = 0x00004000  # Bit set if the operand is a scalar value
    BIT       = 0x00008000  # Bit set if the operand is a bit value
    BYTE      = 0x00010000  # Bit set if the operand is a byte value
    WORD      = 0x00020000  # Bit set if the operand is a 2-byte value
    QUADWORD  = 0x00040000  # Bit set if the operand is an 8-byte value
    SIGNED    = 0x00080000  # Bit set if the operand is a signed value
    FLOAT     = 0x00100000  # Bit set if the operand is a float value
    COP       = 0x00200000  # Bit set if the operand is a co-processor value
    DYNAMIC   = 0x00400000  # Bit set if the operand is dynamically defined given some processorContext.  If bit is set then the SCALAR or ADDRESS bit must be set.
'''

