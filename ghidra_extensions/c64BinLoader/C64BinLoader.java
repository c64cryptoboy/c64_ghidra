/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package c64binloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.HexLong;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class C64BinLoader extends AbstractProgramWrapperLoader {
    public static final String VERSION = "v1.0";

    public static final String OPTION_LOAD_FIRST_TWO_BYTES = "Load first two bytes?";
    public static final String OPTION_LOAD_ADDRESS = "Load address";
    public static final String OPTION_ENTRY_ADDRESS = "Entry address (if known)";
    public static final String OPTION_OVERLAY = "Overlay?";
    public static final String OPTION_CREATE_STACK = "Create stack?";
    
    @Override
    public String getName() {
        // This name must match the name of the loader in the .opinion files.
        // However, 6502 doesn't seem to have a processor opinion file
        return "c64BinLoader";
    }

    
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Arbitrary C64 ML files have no standard headers by which we can figure out if they
        // are valid for this custom loader.  Check for common ".prg" and ".bin" extensions.
        String name = provider.getFile().getName().toLowerCase();
        if (!(name.endsWith(".prg") || name.endsWith(".bin"))) {
            return loadSpecs;  // wrong extension, don't offer this loader
        }
        
        if (provider.length() < 3 || provider.length() > 0xffff) {
            return loadSpecs;  // If not a sensible size, then don't offer this loader
        }
        
        int imageBase = 0;
        boolean preferred = true;
                
        loadSpecs.add(
            new LoadSpec(this, imageBase, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), preferred));        
        
        return loadSpecs;
    }
    
    
    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException, IOException {

        log.appendMsg(getName() + " (" + VERSION + ") loading \"" + provider.getFile().getName() + "\"");

        String loadAddrStr, entryAddrStr;
        Long entry = null;
        Boolean createStack = null;
        Long loadAddr = 0L;        
        int binContentStart = 2; // content normally starts two bytes in
        boolean overlay;
        
        // get options
        if ((Boolean)getValForNamedOption(options, OPTION_LOAD_FIRST_TWO_BYTES)) {
            binContentStart = 0;            
        }
        
        loadAddrStr = (String)getValForNamedOption(options, OPTION_LOAD_ADDRESS);
        if (loadAddrStr.length() > 0) {
            loadAddr = Long.parseLong(loadAddrStr, 16);    
        }
        
        entryAddrStr = (String)getValForNamedOption(options, OPTION_ENTRY_ADDRESS);
        if (entryAddrStr != null && entryAddrStr.length() > 0) {
            entry = Long.parseLong(entryAddrStr, 16);        
        }
        
        overlay = (Boolean)getValForNamedOption(options, OPTION_OVERLAY);

        createStack = (Boolean)getValForNamedOption(options, OPTION_CREATE_STACK);
        
        // perform load
        Memory mem = program.getMemory();
        FlatProgramAPI api = new FlatProgramAPI(program);
        MemoryBlock mb;
        InputStream bytes = provider.getInputStream(binContentStart);
        long bytesLen = provider.length() - binContentStart;
        String blockName = provider.getFile().getName();
        Address loadAddress = api.toAddr(loadAddr);

        try
        {
            mb = mem.createInitializedBlock(blockName, loadAddress, bytes, bytesLen, monitor, overlay);
            anythingGoes(mb);
        } catch (Exception e) {
            log.appendException(e);
            // overlay == true allows loaded code to use already-loaded addresses, but in a new address space
            throw new IOException("Could not create block \"" + blockName + "\", maybe try overlay option?");            
        }

        if (createStack) {
            try
            {
                mb = mem.createInitializedBlock("STACK", api.toAddr(0x0100), 0xff, (byte)0x00, monitor, false);
                anythingGoes(mb);
            } catch (Exception e) {          
                log.appendException(e);
            }
        }

        if (entry != null) {
            api.addEntryPoint(api.toAddr(entry));
            //api.createFunction(api.toAddr(entry), "_entry");
        }

        // Mapped I/O (that's never banked out)
        /* Moving to plugin instead, since inappropriate for 1541 code
        try {
            api.createLabel(api.toAddr(0x0000), "D6510", true);
            api.createLabel(api.toAddr(0x0001), "R6510", true);    
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
    }

    
    // full permissions on block
    private void anythingGoes(MemoryBlock mb) {
        mb.setRead(true);
        mb.setWrite(true);
        mb.setExecute(true);        
    }
    
    
    // override method in AbstractProgramLoader class
    @Override
    protected void createDefaultMemoryBlocks(Program program, Language language, MessageLog log) {
        // The 6502.pspec has default memory blocks that I don't want; these are
        // ZERO_PAGE and a STACK without execute priv.  This override keeps that from
        // happening.  In the load(), we can recreate STACK if we want.
        return;
    }

    
    // override method in Loader class
    @Override
    public boolean supportsLoadIntoProgram() {
        return true;
    }    
    
    
    // override method in AbstractProgramWrapperLoader class
    @Override
    public LoaderTier getTier() {
        return LoaderTier.UNTARGETED_LOADER;
    }

    
    @Override
    public int getTierPriority() {
        return 99;
    }

    
    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram) {

        int binaryStartAddr = 0;
        try {
            binaryStartAddr = (provider.readByte(0x0) & 0xff) + (provider.readByte(0x1) & 0xff) * 256;
        } catch (IOException e) {
            e.printStackTrace();
        }
        String binaryStartAddrHexStr = Integer.toHexString(binaryStartAddr);
        
        List<Option> list = new ArrayList<Option>();

        list.add(new Option(OPTION_LOAD_FIRST_TWO_BYTES, false, Boolean.class, 
            Loader.COMMAND_LINE_ARG_PREFIX + "-loadFirstTwoBytes"));         

        list.add(new Option(OPTION_LOAD_ADDRESS, binaryStartAddrHexStr, String.class,
            Loader.COMMAND_LINE_ARG_PREFIX + "-loadAddr"));

        list.add(new Option(OPTION_ENTRY_ADDRESS, "", String.class,
            Loader.COMMAND_LINE_ARG_PREFIX + "-entryAddr"));

        list.add(new Option(OPTION_OVERLAY, false, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-overlay"));
        
        list.add(new Option(OPTION_CREATE_STACK, true, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-createStack"));     
        
        return list;
    }
    
    
    @Override
    // Returns null if all Options are valid.  On error, returns a error message String.
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        Boolean loadFirstTwoBytes, createStack; 
        HexLong loadAddr = null;
        HexLong entry = null;
        String loadAddrStr, entryStr;    
        long loadStart, loadEnd;
        long codeLen = 0;

        try {
            loadFirstTwoBytes = (Boolean)getValForNamedOption(options, OPTION_LOAD_FIRST_TWO_BYTES);
            loadAddrStr = ((String)getValForNamedOption(options, OPTION_LOAD_ADDRESS)).trim();                    
            entryStr = ((String)getValForNamedOption(options, OPTION_ENTRY_ADDRESS)).trim();
            createStack = (Boolean)getValForNamedOption(options, OPTION_CREATE_STACK);
        } catch (IOException e) {
            return "Error: cannot retreive option";
        }

        try {
            codeLen = provider.length();
        } catch (IOException e) {
            return "Error: unable to measure program length";
        }
        if (!loadFirstTwoBytes) {
            codeLen -= 2;
        }

        // validate load address
        if (loadAddrStr.length() == 0) {
            loadAddr = new HexLong(0);
        } else {
            loadAddr = getHexValForHexString(loadAddrStr);
            if (loadAddr == null) {
                return "\"" + loadAddrStr + "\" is not valid hex";
            }            
        }
        long maxLoadAddr = 0xffff - codeLen;
        if (loadAddr.longValue() < 0 || loadAddr.longValue() > maxLoadAddr) {
            return "load addr range $0000 to $" + Long.toHexString(maxLoadAddr);
        }        

        loadStart = loadAddr.longValue();  // inclusive
        loadEnd = loadStart + codeLen;     // exclusive
        
        // validate entry address
        if (entryStr.length() > 0) {
            entry = getHexValForHexString(entryStr);
            if (entry == null) {
                return "\"" + entryStr + "\" is not valid hex";
            }
            if (entry.longValue() < loadStart || entry.longValue() > loadEnd) {
                return "entry addr range $" + Long.toHexString(loadStart) + " to $" + Long.toHexString(loadEnd);
            }
        }

        // validate room for stack block
        if (createStack) {
            if ((loadStart <= 0x1ff) && (loadEnd > 0x100)) {
                return "stack block would overlap with loaded code block";
            }
        }    
        
        return null; // null here means success
    }

    
    protected Object getValForNamedOption(List<Option> options, String optionName) throws IOException {
        // https://ghidra.re/ghidra_docs/api/ghidra/app/util/Option.html        
        for (Option option : options) {
            if (option.getName().equals(optionName)) {
                return option.getValue();
            }
        }
        throw new IOException("Error: option not found");
    }
    
    
    protected void setValForNamedOption(List<Option> options, String optionName, Object value) throws IOException {
        for (Option option : options) {
            if (option.getName().equals(optionName)) {    
                option.setValue(value);
                return;
            }
        }
        throw new IOException("Error: option not found");        
    }


    // return a HexLong instance, or null if string is not valid hex
    protected HexLong getHexValForHexString(String hexStr) {
        hexStr = hexStr.trim().toLowerCase();
        if (hexStr.startsWith("$")) { // 8-bit style
            hexStr = hexStr.substring(1);
        }
        else if (hexStr.startsWith("0x")) {
            hexStr = hexStr.substring(2);
        }
        if (!hexStr.matches("[0-9a-f]+")) {
            return null; // null here means not success
        }

        return new HexLong(Long.parseLong(hexStr, 16));
    }

}
