# Checks the program for Double Free Vulnerabilities in Windows x64 Applications

'''
Things to add/work on for tracing: 

Indirect function calls/function pointer
https://www.diffchecker.com/qdoX8gc5
https://www.geeksforgeeks.org/function-pointer-in-c/

RDI in free() being assigned via XCHG instruction
'''

program_name = currentProgram.getName()
print("Searching {} for Double Free issues...\n".format(program_name))

DYNAMIC = 4194304
ADDRESS = 8192
DYNAMIC_ADDRESS = DYNAMIC + ADDRESS # This is a ptr memory address like MOV qword ptr [RSP + 0x20], R14

'''
Utilizes the relocation table within the executable to locate the free function.
Because it's a relocation, we need to grab the reference to find the real jump table.
Returns array of all free() addresses from the reloctable.
'''
def grabLinuxFreeFunctions():
    reloc_table = currentProgram.getRelocationTable()
    relocs = reloc_table.getRelocations()
    
    free_function_list = []
    while relocs.hasNext():
        rel = relocs.next()
        if rel.getSymbolName() == "free":
            free_reloc_addr = rel.getAddress()
            refs = getReferencesTo(free_reloc_addr)
            for ref in refs:
                free_addr = ref.getFromAddress()
                free_function_list.append(getFunctionAt(free_addr))
            return free_function_list

'''
Utilizes the symbol table within the executable to locate the free function. 
Returns array of all free() addresses from the symtable (including any jump table stuff)
'''
def grabWindowsFreeFunctions(): 
    symbol_table = currentProgram.getSymbolTable()
    free_symbols = symbol_table.getExternalSymbols("free")

    free_function_list = []
    while free_symbols.hasNext():
        sym = free_symbols.next()
        free_function_list.append(getFunctionAt(sym.getAddress()))
        
    return free_function_list
   
   
'''
Input: array of functions
Obtains all reference calls to the functions provided in the list. 
Returns an array of dictionaries.
'''    
def listRefCalls(function_list):
    call_info_list = []
    for function in function_list:
        func_entry = function.getEntryPoint()
        refs = getReferencesTo(func_entry)
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                try:
                    call_func = getFunctionContaining(call_addr).getName()
                    call_addr_offset = call_addr.getOffset()
                    call_info = {
                        'address': call_addr,
                        'function': call_func,
                        'offset': call_addr_offset
                    }
                    call_info_list.append(call_info)
                except:
                    print('Failed to find function for XREF at {}, skipping.'.format(call_addr))
                    continue
    return call_info_list

'''
This function calculates the stack offset caused by a CALL instruction (and general stack movement).

# Need to add a tracking function for Stack stuff.
Since we're going backwards we will see something like MOV RBP, qword ptr [RSP + 0xa0]
We gotta track all stack changes so we know where the stack is and what parameter it is
SUB RSP, 0x50 -> -0x50 (80)
ADD RSP, 0x10 -> +0x10 (16)
PUSH REG -> -0x8 (8)
POP REG -> +0x8 (8)
Start of the function? -0x8 b/c a call always adds the return address to the stack to make sure it can get back.

Doing all this will give us our RSP+0xZZ value we need to search for in other functions.
'''
def traceStackParameters(current_instr):
    stack_offset = int(current_instr.getInputObjects()[0].getValue())
    while True:
        if current_instr.getAddress() == getFunctionContaining(current_instr.getAddress()).getEntryPoint():
            if current_instr.getMnemonicString() == "PUSH":
                stack_offset -= 16 # To account for return value caused by CALL and PUSH
            elif current_instr.getMnemonicString() != "POP":
                stack_offset -= 8 # Account for just the return, If for WHATEVER reason there is a POP, then the offset would cancel eachother out so no need to add or subtract. 
            return stack_offset
        elif current_instr.getMnemonicString() == "SUB" and str(current_instr.getInputObjects()[0] == "RSP"):
            scalar_value = int(current_instr.getInputObjects()[1].getValue()) # Returns the scalar for the instruction, ex: SUB RSP, 0x50
            stack_offset -=  scalar_value
        elif current_instr.getMnemonicString() == "ADD" and str(current_instr.getInputObjects()[0] == "RSP"):
            scalar_value = int(current_instr.getInputObjects()[1].getValue()) # Returns the scalar for the instruction, ex: ADD RSP, 0x
            stack_offset += scalar_value
        elif current_instr.getMnemonicString() == "PUSH":
            stack_offset -= 8
        elif current_instr.getMnemonicString() == "POP":
            stack_offset += 8
        current_instr = current_instr.getPrevious()

'''
Grabs all references for the current function, and begins an inter function trace for each
starting at the instruction prior to the initial referenced call.
This will get called everytime a trace hits the top of a function.
'''
def traceExterCallInstructions(inter_trace, stack_ops=None):
    # Just grab the last value in the array to get the earliest instruction in the function.
    earliest_instr = inter_trace[-1]
    current_function = getFunctionContaining(earliest_instr.getAddress())
    
    # Grab the references for the function
    raw_func_refs = listRefCalls([current_function])
    
    # Check if the trace is unsuccessful because it hit the entry of the program.
    if not raw_func_refs:
        print("Failed to trace through calls, scanned all the way to entry.")
        return None
    else:
        func_refs = []
        for ref in raw_func_refs:
            if ref['function'] != current_function.getName(): # We gotta remove any instances of recursion to not waste time.
                func_refs.append(ref)
        
        for ref in func_refs:
            if stack_ops: # If we got stack operations we assign them as the "target_register" just to keep everything consistent
                target_register = stack_ops
            else:
                target_register = earliest_instr.getOpObjects(1)
                target_register = [str(i) for i in target_register]
            start_instr = getInstructionAt(ref['address']) # The start instr will be the initial call, but we will be searching starting prior to it.
            ntrace = inter_trace + [start_instr]
            return traceInterFuncInstructions(start_instr.getPrevious(), target_register, False, ntrace, 10) # We're setting a max count of 10 for the initial instruction so we dont get a FP. This can be adjusted.


'''
Runs through the MOV instructions until it gets to the RAX source.
at that point it grabs the CALL preceeding it. 
It traces the stack if it hits a DYNAMIC_ADDRESS (pointer MOV) and is RSP, 
and traces external function references/calls to find what it needs to find.

Returns an array containing all MOV and CALL instructions in the trace.
'''
def traceInterFuncInstructions(current_instruction, target_register, return_check, trace_arr=[], max_count=100):
    call_trace = trace_arr
    count = 0
    while True:
        count += 1
        # Gotta first check if we found the *alloc call we're looking for via the return_check.
        if return_check:
            if current_instruction.getMnemonicString() == "CALL":
                call_trace.append(current_instruction)
                return call_trace
        else:
            # We need to check if we're at the start of a function, obvious can't be reliably tracing if we have no idea where we are.
            if current_instruction.getAddress() == getFunctionContaining(current_instruction.getAddress()).getEntryPoint():
                if not call_trace:
                    print('Failed to trace instructions within the function.')
                    return None
                call_trace = traceExterCallInstructions(call_trace)
                return call_trace # Due to recursion, we will hit the CALL return, allowing us to also return here. 
            elif current_instruction.getMnemonicString() == "MOV": # We're only watching register changes from MOV
                src_value = current_instruction.getOpObjects(0) # Bc we're going backwards in instructions, the src is really the result object
                src_value = [str(i) for i in src_value] # Need them to all be strings
                if src_value == target_register:
                    call_trace.append(current_instruction)
                    operand_type = current_instruction.getOperandType(1) # Used to check if we're dealing with a stack value
                    dst_value = current_instruction.getOpObjects(1) # Bc we're going backwards in instructions, the dst is really the input object
                    dst_value = [str(i) for i in dst_value] # Need them to all be strings
                    # We need to check if the value is on the stack, so we have to track it through stack changes.
                    if operand_type == DYNAMIC_ADDRESS:
                        if dst_value[0] == 'RSP': # If it's RSP we're dealing with changes to the current stack, which is an indicator it's being called from a function.
                            stack_offset = traceStackParameters(current_instruction)
                            stack_ops = [dst_value[0],str(hex(stack_offset))] # Needs to look like ['RSP', '0x8']
                            call_trace = traceExterCallInstructions(call_trace, stack_ops)
                            return call_trace
                        else: # Really only if it's RBP, which is an indicator that the value is simply being stored on the stack near the base pointer.
                            return traceInterFuncInstructions(current_instruction.getPrevious(), dst_value, False, call_trace)
                            
                    else:
                        if dst_value == ['RAX']: # We've found the return source, just need to find the call.
                            return traceInterFuncInstructions(current_instruction.getPrevious(), dst_value, True, call_trace)
                        else:
                            return traceInterFuncInstructions(current_instruction.getPrevious(), dst_value, False, call_trace)
        if count == max_count: # Setting the max count so that we dont get any FPs for the exter-func trace.
            print('Failed to find any more register tracings within {} instructions.'.format(str(count)))
            break
        current_instruction = current_instruction.getPrevious()

 
'''
Loops through all free references and traces them all the way to the *alloc call.
Returns an array of arrays of each full instruction trace.
'''
def obtainAllFunctionTraces(fcall_info_list, target_reg):
    full_trace_list = [] # An array of arrays containing all traces instructions from *alloc to Free.
    for call_info in fcall_info_list:
        trace_array = []
        func_call_instr = getInstructionAt(call_info['address'])
        trace_array.append(func_call_instr)

        current_instruction = func_call_instr
        count = 0
        # We're going to loop through until we find the first instruction that is the first parameter of the free() call.
        while True:
            count += 1
            if current_instruction.getMnemonicString() == "MOV": # getResultObjects checks if the src has an address or register (so no scalars)
                src_value = current_instruction.getOpObjects(0) # Bc we're going backwards in instructions, the src is really the result object
                src_value = [str(i) for i in src_value] # Need them to all be strings
                if src_value == target_reg: # The first source value will be the first parameter of the specified architecture/os
                    dst_value = current_instruction.getOpObjects(1) # Bc we're going backwards in instructions, the dst is really the input object
                    dst_value = [str(i) for i in dst_value] # Need them to all be strings
                    trace_array.append(current_instruction)
                    call_trace = traceInterFuncInstructions(current_instruction, dst_value, False, []) # We then need to trace all the way back to the source *alloc call.
                    # Verify that the trace was successful or not.
                    if not call_trace:
                        print("Trace unsuccessful for {}: {}, skipping.".format(trace_array[0].getAddress(), trace_array[0]))
                    else:
                        trace_array = trace_array + call_trace 
                        trace_array = trace_array[::-1] # Reverse it so the *alloc call is the first in the array (because confusing otherwise).
                        full_trace_list.append(trace_array) 
                    break
            if count == 100:
                break
            current_instruction = current_instruction.getPrevious()
    return full_trace_list


'''
enumerates a list for duplicates of a specific item.
'''
def indices(lst, item):
    return [i for i, x in enumerate(lst) if x == item]


'''
Checks the traces for double free issues by matching the *alloc handles for any duplicates.
Returns dictionary with the dict value containing the vuln traces.
'''
def checkForDoubleFree(full_trace_list):
    mem_addr_list = []
    for trace_list in full_trace_list:
        mem_addr_list.append(trace_list[0].getAddress())
    
    # We're now going to look for any duplicate memory addresses as that proves a specific *alloc handle is being freed twice.
    raw_dupes_dict = dict((x, indices(mem_addr_list, x)) for x in set(mem_addr_list) if mem_addr_list.count(x) > 1)
    double_free_vulns = {}
    for dupe_addr in raw_dupes_dict.keys():
        vuln_traces = []
        for index in raw_dupes_dict[dupe_addr]:
            vuln_traces.append(full_trace_list[index])
        double_free_vulns[dupe_addr] = vuln_traces
    return double_free_vulns


'''
Returns simple dictionary of formatted call to provide external reference name and symbol name.
'''
def getCallInformation(call_instr):
    call_ptr_addr = call_instr.getOpObjects(0)[0]
    if getReferencesFrom(call_ptr_addr):
        ext_ref_name = getReferencesFrom(call_ptr_addr)[0]
    else:
        ext_ref_name = None
    sym_name = getSymbolAt(call_ptr_addr)
    
    call_info_dict = {
        'ext_ref_name': ext_ref_name,
        'sym_name': sym_name
    }
    return call_info_dict


'''
Formats/prints what was returned from checkForDoubleFree()
'''
def formatVulnOutput(vuln_dict):
    for vuln in vuln_dict.keys():
        alloc_instr = getInstructionAt(vuln)
        alloc_info = getCallInformation(alloc_instr)
        print("POTENTIAL DOUBLE FREE VULN USING HANDLE ({}): {} ; {} / {}".format(alloc_instr.getAddress(), alloc_instr, alloc_info['sym_name'], alloc_info['ext_ref_name']))
        print("-------------")
        for trace in vuln_dict[vuln]:
            for instr in trace:
                if instr.getMnemonicString() == "CALL":
                    call_infos = getCallInformation(instr)
                    if call_infos['ext_ref_name']:
                        print("{}: {} ; {} / {}".format(instr.getAddress(), instr, call_infos['sym_name'], call_infos['ext_ref_name']))
                    else:
                        print("{}: {} ; {}".format(instr.getAddress(), instr, call_infos['sym_name']))
                else:
                    print("{}: {}".format(instr.getAddress(), instr))
            print('')


'''
Fancy main function.
'''
def main():
    # Has to be 64bit
    if str(currentProgram.getLanguageID()) != "x86:LE:64:default":
        print("Architecture not supported.")
        return 0

    os_type = str(currentProgram.getExecutableFormat())
    # If it's Windows, we need to grab free() differently, and set the first register to RCX due to calling convention
    if os_type == "Portable Executable (PE)":
        free_list = grabWindowsFreeFunctions()
        target_reg = ['RCX']
    
    # If it's Linux, we need to grab free() differently, and set the first register to RDI due to calling convention    
    elif os_type == "Executable and Linking Format (ELF)":
        free_list = grabLinuxFreeFunctions()
        target_reg = ['RDI']
    else:
        print("Unknown/Unsupported OS.")
        return 0
    
    if not free_list:
        print('No symbols for free() were identified.')
        return 0

    fcall_info_list = listRefCalls(free_list) # An array of dictionaries containing address, function name, and offset of all free reference calls
    full_trace_list = obtainAllFunctionTraces(fcall_info_list, target_reg)
    
    vuln_dict = checkForDoubleFree(full_trace_list)
    
    if vuln_dict:
        formatVulnOutput(vuln_dict)
    else:
        print('No potential double free vulnerabilities were identified.')

    
if __name__ == '__main__':
    main()
