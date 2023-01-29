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
package c64diraccesscmdsearch;

import java.nio.charset.StandardCharsets;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


public class C64DirAccessCmdSearchAnalyzer extends AbstractAnalyzer {

	public C64DirAccessCmdSearchAnalyzer() {
		super("C64DirAccessCmdSearch", "Find direct-access drive commands, even if fixed XOR mask applied", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
	}


	@Override
	public boolean getDefaultEnablement(Program program) {
		return false; // Return true if analyzer should be enabled by default
	}


	@Override
	public boolean canAnalyze(Program program) {
	    // Test to see if analyzer is appropriate for the program
	    return program.getLanguageID().getIdAsString().equals("6502:LE:16:default");
	}

	@Override
	public void registerOptions(Options options, Program program) {
	    // no user options (yet)
	}

    /*
     * added called when the requested information type has been added, or when a specific area
     * of the program has been requested to be analyzed by user.
     * 
     * from public enum AnalyzerType:
     *   BYTE_ANALYZER("Byte Analyzer", "Triggered when bytes are added (memory block added)."),
     *   INSTRUCTION_ANALYZER("Instructions Analyzer", "Triggered when instructions are created."),
     *   FUNCTION_ANALYZER("Function Analyzer", "Triggered when functions are created."),
     *   FUNCTION_MODIFIERS_ANALYZER("Function-modifiers Analyzer", "Triggered when a function's modifier changes"),
     *   FUNCTION_SIGNATURES_ANALYZER("Function-Signatures Analyzer", "Triggered when a function's signature changes."),
     *   DATA_ANALYZER("Data Analyzer", "Triggered when data is created.");
     */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

	    // Commodore PETSCII close enough to ASCII that this works:
	    String[] searchStrs = {"U1", "U2", "M-R", "M-W", "M-E", "B-P", "B-R", "B-W", "B-E", "B-A", "B-F"};

	    Memory mem = program.getMemory();
	    SetCommentCmd cmd;
	    boolean cmdResult;

	    // for each search string
	    for (String searchStr : searchStrs) {
	        byte[] searchBytes = searchStr.getBytes(StandardCharsets.US_ASCII);
	        byte[] xorSearchBytes = new byte[searchBytes.length];
	        monitor.setMessage("Searching for " + searchStr);
	        String commentStr;
	        
	        // for each fixed XOR mask for a search string
	        for (int xorMask = 0; xorMask < 256; xorMask++) { // (mask 0x00 is identity)
	            for (int i = 0; i < searchBytes.length; i++) {
	                xorSearchBytes[i] = (byte)(searchBytes[i] ^ xorMask) ;
	            }
	            Address searchStartAddr = mem.getMinAddress();
	            
    	        // find all matches for the XORed search string
    	        while (searchStartAddr != null) {
    	            searchStartAddr = mem.findBytes(searchStartAddr, xorSearchBytes, null, true, monitor);
    	            if (searchStartAddr != null ) {
    	                commentStr = "found \"" + searchStr + "\" with XOR mask 0x" + String.format("%02X ", xorMask);
    	                cmd = new SetCommentCmd(searchStartAddr, CodeUnit.EOL_COMMENT, commentStr);
    	                cmdResult = cmd.applyTo(program);
    	                if (!cmdResult) {
    	                    return false;  // analyzer failed
    	                }	                
    	                searchStartAddr = searchStartAddr.add(1); // advance search resume point
    	            }
    	        }
	        }
	    }

		return true; // analyzer success
	}

    /**
     * Called when an auto-analysis session ends. This notifies the analyzer so it can clean up any 
     * resources that only needed to be maintained during a single auto-analysis session.
     * @param program the program that was just completed being analyzed
     */
	@Override
    public void analysisEnded(Program program) {
        // no cleanup necessary after analysis
    }

}

