from ghidra.program.model.address import AddressSet

def run():
    memory = currentProgram.getMemory()
    
    # make sure something's selected
    if currentSelection is None or currentSelection.isEmpty():
        print "Error: Must select data and/or instructions to XOR"
        return

    # get XOR byte val
    while True:
        input = askString('XOR byte over the range $%s-$%s'
                % (currentSelection.getMinAddress(), currentSelection.getMaxAddress()),
                'Enter XOR hex byte' )
        tmp = input.strip()
        if tmp[0] == '$':
            tmp = input[1:] # drop optional '$' prefix
        try:
            xor_byte = int(tmp, 16) # can handle '0x' optional prefix
        except ValueError as ve:
            print('Error: "%s" is not valid hex' % input)
            continue
        if not 0 <= xor_byte <= 255:
            print('Error: hex byte must be in the range $00-$ff')
            continue
        break

    # Can't modify memory where there's defined instructions without first doing a "clear code bytes"
    # in the GUI, or the API equivalent:
    clearListing(currentSelection)
   
    addr_itter = currentSelection.getAddresses(True) # True == iterate accending
    for addr in addr_itter:
        setByte(addr, getByte(addr) ^ xor_byte)

run()