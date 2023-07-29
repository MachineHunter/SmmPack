//retrive protocol interface structure address of the protocol this UEFI module installs (its a prototype code that needs more optimazation to make it work on various environment)
//@author MachineHunter
//@category SmmPack
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;
import java.util.List;
import java.io.*;
import ghidra.program.model.address.Address;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.data.DataType;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.FunctionPrototype;


public class GetProtocolInterfaceStructureAddress extends HeadlessScript {
    private ClangNode process_clang_node(ClangNode cn) {
		 int numChildren = cn.numChildren();
		 if(numChildren!=0) {
			 int i;
			 for(i=0; i<numChildren; i++) {
				 ClangNode child = cn.Child(i);
				 if(String.valueOf(child).contains("InstallMultipleProtocolInterfaces")) {
					 return process_clang_node(child);
				 }
			 }
		 }
		 return cn;
	 }

    public void run() throws Exception {
		 DataType bs = currentProgram.getDataTypeManager().getDataType("/behemot.h/EFI_BOOT_SERVICES");
		 ListAccumulator<LocationReference> accumulator = new ListAccumulator<>();

		 ReferenceUtils.findDataTypeReferences(
				 accumulator,
				 bs,
				 "InstallMultipleProtocolInterfaces",
				 currentProgram,
				 monitor
				 );

		 println("InstallMultipleProtocolInterfaces call locations:");
		 for(LocationReference locationReference : accumulator) {
			 println("0x" + String.valueOf(locationReference.getLocationOfUse()));
			 Function f = getFunctionContaining(locationReference.getLocationOfUse());

			 DecompInterface dif = new DecompInterface();
			 dif.openProgram(currentProgram);
			 /*
			  *DecompileResults dr = dif.decompileFunction(f, 2000, monitor);
			  *HighFunction hf = dr.getHighFunction();
			  *println(String.valueOf(hf));
			  */

			 /*
			  *HighFunction hf = dif.decompileFunction(f,1,monitor).getHighFunction();
			  *HighSymbol param = hf.getFunctionPrototype().getParam(0);
			  *println(String.valueOf(param.getName()));
			  */

			 DecompileResults dr = dif.decompileFunction(f,1,monitor);
			 DecompiledFunction df = dr.getDecompiledFunction();
			 /*
			  *println("================== C decompiled Result =====================");
			  *println(df.getC());
			  *println("============================================================");
			  */

			 ClangTokenGroup ctg = dr.getCCodeMarkup();
			 /*
			  *ArrayList<ClangLine> lines = DecompilerUtils.toLines(ctg);
			  *for(ClangLine cl : lines) {
			  *   println(">>>" + cl.toString());
			  *}
			  */
			 int i,j;
			 ClangNode res = null;
			 for(i=0; i<ctg.numChildren(); i++) {
				 ClangNode cn = ctg.Child(i);
				 if(String.valueOf(cn).contains("InstallMultipleProtocolInterfaces")) {
					 res = process_clang_node(cn);
				 }
			 }

			 if(res!=null) {
				 res = res.Parent();
				 String inst = String.valueOf(res);
				 println("found clang node: " + inst);
				 String[] arr = inst.split("InstallMultipleProtocolInterfaces")[1].split(",");
				 // i=0       =>  handle
				 // i=1       =>  guid
				 // i=2,4,... =>  protocol interfaces structures
				 // i=last    =>  NULL GUID
				 for(i=2; i<arr.length-1; i+=2) {
					 String sympis = arr[i];
					 if(sympis.contains("(")) { // remove type cast
						 sympis = sympis.split(")")[1];
					 }
					 if(sympis.contains("&")) { // remove & operator
						 sympis = sympis.split("&")[1];
					 }
					 Symbol sym = currentProgram.getSymbolTable().getGlobalSymbols(sympis).get(0);
					 Address start = sym.getAddress();
					 while(getDataAt(start)!=null && getDataAt(start).isPointer()) {
						 long addr = start.subtract(currentProgram.getImageBase());
					    println(">>> " + sympis + ": 0x" + String.valueOf(start) + " (" + String.valueOf(addr) + ")");
						 // write to file
						 try {
							 String tmp = System.getenv("TEMP");
							 tmp += "\\output.txt";
							 PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(tmp, true)));
							 pw.println(String.valueOf(addr));
							 pw.close();
						 } catch(IOException e) {}
						 start = start.add(8);
					 }
				 }
			 }
		 }
    }

}
