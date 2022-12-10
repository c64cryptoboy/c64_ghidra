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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.io.InputStream;

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
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;

/*
 * Notes:
 * - https://github.com/NationalSecurityAgency/ghidra/blob/a64afa37a7873fefad84c7b994a50acf02beb062/Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/AbstractProgramLoader.java 
 * 
 * TODO:
 * - 
 * 
 */

public class c64BinLoaderLoader extends AbstractProgramWrapperLoader {

	public static final String VERSION = "v0.1.1";
	
	public static final String OPTION_LOAD_FIRST_TWO_BYTES = "Load first two bytes?";
	public static final String OPTION_LOAD_ADDRESS = "Load address";
	public static final String OPTION_ENTRY_ADDRESS = "Entry address (if known)";
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
		// are valid for this custom loader.  But programs extracted from DirMaster should
		// end with ".PRG", so we can at least check that
		String name = provider.getFile().getName().toLowerCase();
		if (!(name.endsWith(".prg") || name.endsWith(".bin"))) {
			return loadSpecs;
		}
		
		if (provider.length() < 3 || provider.length() > 0xffff) {
			return loadSpecs;
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

		// So many loader examples online that use monitor.setMessage(string) to provide feedback
		// however, I can't tell where this text gets displayed in the GUI, if at all.
		// To see feedback in the Import's Additional Information section after a load, I'm
		// using log.appendMsg(string) instead.
		// Note, neither log nor monitor strings show up in
		//    C:\Users\USERNAME\.ghidra\.ghidra_10.2.2_PUBLIC\application.log
		log.appendMsg(getName() + " (" + VERSION + ") loading \"" + provider.getFile().getName() + "\"");

		Long loadAddr = null;
		Long entry = null;
		Boolean createStack = null;
		int binContentStart = 2; // content normally starts two bytes in
		
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_LOAD_FIRST_TWO_BYTES)) {
				if ((Boolean)option.getValue()) {
					binContentStart = 0;
				}
			}
			else if (optName.equals(OPTION_LOAD_ADDRESS)) {
				loadAddr = Long.parseLong((String)option.getValue(), 16);
			}
			else if (optName.equals(OPTION_ENTRY_ADDRESS)) {
				String tmp = (String)option.getValue();
				if (tmp != null && tmp.length() > 0) {
					entry = Long.parseLong(tmp, 16);
				}
			}
			else if (optName.equals(OPTION_CREATE_STACK)) {
				createStack = (Boolean)option.getValue();				
			}			
		}

		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);

		// "if true, the block will be created as an OVERLAY which means that a new overlay address
		// space will be created and the block will have a starting address at the same offset as
		// the given start address parameter, but in the new address space."
		boolean overlay = false;
		MemoryBlock mb;
		InputStream bytes = provider.getInputStream(binContentStart); // TODO: Right base class here?
		long bytesLen = provider.length() - binContentStart;
		String blockName = provider.getFile().getName();
		Address loadAddress = api.toAddr(loadAddr);

		try
		{
			mb = mem.createInitializedBlock(blockName, loadAddress, bytes, bytesLen, monitor, overlay);
			anythingGoes(mb);
		} catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to load c64 binary");			
		}

		if (createStack) {
			try
			{
				mb = mem.createUninitializedBlock("STACK", api.toAddr(0x0100), 0xff, false);
				anythingGoes(mb);
			} catch (Exception e) {  		
				log.appendException(e);
			}
		}

		if (entry != null) {
			api.addEntryPoint(api.toAddr(entry));
			//api.createFunction(api.toAddr(entry), "_entry");
		}

		// Mapped I/O			
		try {
			api.createLabel(api.toAddr(0x0000), "6510DDR", true);
			api.createLabel(api.toAddr(0x0001), "BANKING_CASSETTE", true);	
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void anythingGoes(MemoryBlock mb) {
		mb.setRead(true);
		mb.setWrite(true);
		mb.setExecute(true);		
	}
	
	@Override
	protected void createDefaultMemoryBlocks(Program program, Language language, MessageLog log) {
		// The 6502.pspec has default memory blocks that I don't want; these are
		// ZERO_PAGE and STACK (without execute priv).  This override keeps that from
		// happening.  In the load(), I'll recreate STACK (can't just add execute to it, because
		// default memory blocks don't yet exist at load() time).
		return;
	}

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
		String binaryStartAddrHex = Integer.toHexString(binaryStartAddr);
		
		List<Option> list = new ArrayList<Option>();

        list.add(new Option(OPTION_LOAD_FIRST_TWO_BYTES, false, Boolean.class, 
            Loader.COMMAND_LINE_ARG_PREFIX + "-loadFirstTwoBytes"));         

		list.add(new Option(OPTION_LOAD_ADDRESS, binaryStartAddrHex, String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-loadAddr"));

		list.add(new Option(OPTION_ENTRY_ADDRESS, "", String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-entryAddr"));

        list.add(new Option(OPTION_CREATE_STACK, true, Boolean.class,
                Loader.COMMAND_LINE_ARG_PREFIX + "-createStack"));  		
		
		return list;
	}
	
	@Override
	// return null if all Options are valid or an error message String
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		Boolean loadFirstTwoBytes = null;
		HexLong loadAddr = null;
		HexLong entry = null;
		String optName, tmpString;	

		// gather input values and validate (in a horrible, order-independent way)
		for (Option option : options) {
			optName = option.getName();
			if (optName.equals(OPTION_LOAD_FIRST_TWO_BYTES)) {
				loadFirstTwoBytes = (Boolean)option.getValue();
			}
			else if (optName.equals(OPTION_LOAD_ADDRESS)) {
				tmpString = (String)option.getValue();
				if (!tmpString.equals("")) {
					loadAddr = getHexValForHexString(tmpString);
					if (loadAddr == null) {
						return "\"" + tmpString + "\" is not valid hex";
					}
				}
				if (loadAddr == null) {
					loadAddr = new HexLong(0);
				}
			}
			else if (optName.equals(OPTION_ENTRY_ADDRESS)){
				tmpString = (String)option.getValue();
				if (!tmpString.equals("")) {
					entry = getHexValForHexString(tmpString);
					if (entry == null) {
						return "\"" + tmpString + "\" is not valid hex";
					}
				}
			}
		}

		long codeLen = 0;
		try {
			codeLen = provider.length();
		} catch (IOException e) {
			return "Error: unable to measure program length";
		}
		if (!loadFirstTwoBytes) {
			codeLen -= 2;
		}
		
		// additional work after all values gathered
		for (Option option : options) {
			optName = option.getName();		

			if (optName.equals(OPTION_LOAD_ADDRESS)) {
				long maxAddr = 0xffff - codeLen;
				if (loadAddr.longValue() < 0 || loadAddr.longValue() > maxAddr) {
					return "load addr range $0000 to $" + Long.toHexString(maxAddr);
				}
			}
			else if (optName.equals(OPTION_ENTRY_ADDRESS)) {
				if (entry != null) {
					long lowEntry = loadAddr.longValue();
					long highEntry = loadAddr.longValue() + codeLen;
					if (entry.longValue() < lowEntry || entry.longValue() > highEntry) {
						return "entry addr range $" + Long.toHexString(lowEntry) + " to $" + Long.toHexString(highEntry);
					}
				}
			}
		}

		return null; // null here means success
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
