from binaryninja import BinaryView, LowLevelILOperation
from binaryninja import Symbol, SymbolType

import unicorn as uc
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import *

PAGE = 0x1000
MASK64 = (1 << 64) - 1
STACK_TOP, STACK_SIZE = 0x00007FFF00000000, 0x01000000
MAX_WINDOW_SIZE = 25

def is_call_via_rax(il):
    if il.operation not in (LowLevelILOperation.LLIL_CALL, LowLevelILOperation.LLIL_TAILCALL):
        return False
    d = il.dest
    return (d is not None and
            d.operation == LowLevelILOperation.LLIL_REG and
            getattr(d.src, "name", "").lower() == "rax")

def add_rax_rhs_reg(il):
    """Return RHS register name for: rax = rax + <reg>, else None."""
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return None
    if getattr(il.dest, "name", "").lower() != "rax":
        return None
    s = il.src
    if s.operation != LowLevelILOperation.LLIL_ADD:
        return None
    if s.left.operation != LowLevelILOperation.LLIL_REG:
        return None
    if getattr(s.left.src, "name", "").lower() != "rax":
        return None
    if s.right.operation != LowLevelILOperation.LLIL_REG:
        return None
    reg = getattr(s.right.src, "name", "").lower()
    print( f"Found rax = rax + {reg} at {hex(il.address)}" )
    return reg



def sub_rax_rhs_reg(il):
    """Return RHS register name for: rax = rax - <reg>, else None."""
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return None
    if getattr(il.dest, "name", "").lower() != "rax":
        return None
    s = il.src
    if s.operation != LowLevelILOperation.LLIL_SUB:
        return None
    if s.left.operation != LowLevelILOperation.LLIL_REG:
        return None
    if getattr(s.left.src, "name", "").lower() != "rax":
        return None
    if s.right.operation != LowLevelILOperation.LLIL_REG:
        return None
    reg = getattr(s.right.src, "name", "").lower()
    print( f"Found rax = rax - {reg} at {hex(il.address)}" )
    return reg

def u64(x): 
    return x & MASK64

def s64(x):
    x &= MASK64
    return x if x < (1 << 63) else x - (1 << 64)


def mov_reg_imm64(il, target_reg):
    """
    Match <reg> = <const>
    """
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return None
    if getattr(il.dest, "name", "").lower() != target_reg:
        return None
    s = il.src
    if s.operation != LowLevelILOperation.LLIL_CONST:
        return None
    const_val = u64(s.constant)
    print( f"Found mov {target_reg}, {hex(const_val)} at {hex(il.address)}" )
    return const_val


def rax_load_from_constptr_q(il, bv: BinaryView):
    """
    Match: rax = [CONSTPTR].q  -> u64 value, else None.
    """
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return None
    if getattr(il.dest, "name", "").lower() != "rax":
        return None
    s = il.src
    if s.operation != LowLevelILOperation.LLIL_LOAD:
        return None
    a = s.src
    if not a:
        return None

    if a.operation == LowLevelILOperation.LLIL_CONST_PTR:

        print( f"Found rax = [CONSTPTR].q at {hex(il.address)}" )
        data_pointer = bv.read_pointer(a.constant)
        print( f"  qword loaded = {hex(u64(data_pointer))}" )
        return u64(data_pointer)
    return None

def resolve_target_from_window(bv, window, call_addr=None):

    add_reg = None # track register used in the add instruction
    add_idx = None # track index of the add instruction

    sub_reg = None # track register used in the sub instruction
    sub_idx = None # track index of the sub instruction

    # Starting from the bottom up (doesnt make a diff)
    for i in range(len(window)-1, -1, -1):
        # Search for this pattern and return the reg name of rhs
        # to be used to check if reg is where imm64 is moved to 
        r = add_rax_rhs_reg(window[i]) 
        if r:
            add_reg = r
            add_idx = i
            break
        r = sub_rax_rhs_reg(window[i])
        if r:
            sub_reg = r
            sub_idx = i
            break
    # Ignore this window and continue searching for other potential windows
    if add_reg is None and sub_reg is None:
        return (None, None)
    
    imm_val = None  # Tracking imm64 value set to add_reg
    imm_idx = None  # Tracking index of imm64 move instruction

    rax_qword = None # Track the qword loaded into rax
    rax_idx = None  # Tracking index of rax load instruction

    # Starting from the bottom up (doesnt make a diff)
    for i in range(len(window)-1, -1, -1):
        #  <reg> = <const>  (check for immediate value moves)
        il = window[i] #  get the current instruction
        if imm_val is None:
            ## Depending on whether it is an add or sub, we want to check 
            ## that imm64 is moved to that register
            target_reg = add_reg if add_reg is not None else sub_reg
            c = mov_reg_imm64(il, target_reg) # we want to move to the register
            if c is not None:
                imm_val = c
                imm_idx = i
        if rax_qword is None:
            v = rax_load_from_constptr_q(il,bv)
            if v is not None:
                rax_qword = v
                rax_idx = i
        # We can stop searching the window if we found the two patterns
        if imm_val is not None and rax_qword is not None:
            break

    # Make sure we can find all three instructions
    if imm_val is None or rax_qword is None:
        return (None, None)
    
    """ Time to calculate the target address depending on add or sub """
    if sub_reg:
        target = u64(rax_qword - s64(imm_val))
        print( f"Resolved target address: {hex(target)}" )
        seq_start_il = window[min(x for x in (imm_idx, rax_idx, sub_idx) if x is not None)]
        seq_start_addr = seq_start_il.address if seq_start_il is not None else None
        print( f"Sequence start address: {hex(seq_start_addr) if seq_start_addr is not None else 'N/A'}" )
        return target, seq_start_addr
    elif add_reg:
        target = u64(rax_qword + s64(imm_val))
        print( f"Resolved target address: {hex(target)}" )
        seq_start_il = window[min(x for x in (imm_idx, rax_idx, add_idx) if x is not None)]
        seq_start_addr = seq_start_il.address if seq_start_il is not None else None
        print( f"Sequence start address: {hex(seq_start_addr) if seq_start_addr is not None else 'N/A'}" )
        return target, seq_start_addr
    


def disasm_preview_inline(bv, addr: int, max_insns: int = 3, max_chars: int = 120, include_addr: bool = False):
    """Return 'mnemonic1 ; mnemonic2 ; mnemonic3' (optionally with addresses), truncated."""
    parts = []
    cur = addr
    for _ in range(max_insns):
        data = bv.read(cur, 16)
        if not data:
            break
        try:
            tokens, length = bv.arch.get_instruction_text(data, cur)
        except Exception:
            break
        if not length:
            break
        text = "".join(tok.text for tok in tokens)
        parts.append(f"{cur:#x}  {text}" if include_addr else text)
        cur += length
    line = " ; ".join(parts)
    if len(line) > max_chars:
        line = line[:max_chars - 1] + "…"
    return line

def annotate_indirect_callsite(bv, call_addr, target_addr):
    print("annotating indirect callsite...")
    """Annotate the callsite at call_addr with the resolved target_addr."""
    target_addr = u64(target_addr)
    print( f"Annotating callsite at {hex(call_addr)} with target {hex(target_addr)}" )
    try:
        if not bv.get_function_at(target_addr):
            bv.create_user_function(target_addr)
    except Exception as e:
        print(f"Error annotating callsite at {hex(call_addr)}: {e}")
    
    sym_name = f"Resolved_0x{target_addr:x}"

    ## Check for existing symbol in case there are duplicates
    try:
        if not any(s.name == sym_name for s in bv.get_symbols(target_addr)):
            bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, target_addr, sym_name))
    except Exception as e:
        print(f"Error defining symbol at {hex(target_addr)}: {e}")
    
   
    try:
        preview = disasm_preview_inline(bv, target_addr, max_insns=3, max_chars=120, include_addr=False)
        print( f"Preview of target {hex(target_addr)}: {preview}" )
        comment = f"---> 0x{target_addr:016x}"
        if preview:
            comment += f" | {preview}"
        bv.set_comment_at(call_addr, comment)
    except Exception:
        print(f"Error setting comment at {hex(call_addr)}")
        pass
    
def patch_obfuscated_indirect_call(bv: BinaryView, window, call_addr, target:int):
    # NOP all instruction in window before
    for il in window:
        if not bv.convert_to_nop(il.address):
            print( f"[ERROR] - Failed to NOP instruction at {hex(il.address)}" )
    for il in window:
        # We want to patch in e8 <rel32> (size = 5)
        rel32 = target - (window[0].address + 5)
        if -0x80000000 <= rel32 <= 0x7FFFFFFF:
            # Be careful not to write straight at the call address because we will overwrite three bytes into the next iosntruction
            # In this case, I choose to write to the first IL in window

            bv.write(window[0].address, b"\xE8" + int(rel32 ).to_bytes(4, "little", signed=True))
            print( f"Patched direct call E8 {rel32 & 0xffffffff} at {hex(call_addr)}" )
            return True
        else:
            print("tasukete kudasai!!!!!")
            return False    
        

def build_llil_index(fn):
    idx = {}
    ll = fn.llil
    if not ll: return idx
    for bb in ll:
        for ins in bb:
            a = getattr(ins, "address", None)
            if a is None: continue
            idx.setdefault(a, []).append(ins)
    return idx


def load_from_const_pointer(bv, il):
    data = None
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return None
    if not il.src: return None
    if il.src.operation != LowLevelILOperation.LLIL_LOAD: 
        return None
    src = il.src.src
    if not src: 
        return None
    if src.operation != LowLevelILOperation.LLIL_CONST_PTR:
        return None
    ptr_addr = src.constant
    data = bv.read_pointer(ptr_addr)
    print(f"Pointer Value: {ptr_addr} -> {hex(u64(data))}")
    return data

def setup_uc():
    u = Uc(UC_ARCH_X86, UC_MODE_64)

    ## Mapping all segments from BinaryView into Unicorn
    for seg in bv.segments:
        base = seg.start & ~(PAGE - 1)
        size = ((seg.end - base + PAGE - 1)//PAGE)*PAGE
        if size <= 0:
            continue
        
        try:
            # Map memory segment
            u.mem_map(base, size, UC_PROT_READ | UC_PROT_WRITE| UC_PROT_EXEC)
            # Get the data from the segment
            blob = bv.read(base, size) or b""
            if blob:
                u.mem_write(base, blob)
        except: 
            pass
    # Map a stack
    try:
        u.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    except:
        pass

    ## Set rsp and rbp
    u.reg_write(UC_X86_REG_RSP, STACK_TOP - 0x4000)
    u.reg_write(UC_X86_REG_RBP, STACK_TOP - 0x8000)

    ## We want to define map window in case there are invalid memory accesses
    MAP_CHUNK = 0x10000
    def map_window(emu, addr):
        if addr >= 0x0000800000000000: return False
        base = (addr & ~(PAGE-1)) & ~(MAP_CHUNK-1)
        try:
            emu.mem_map(base, MAP_CHUNK, UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC); return True
        except:
            try:
                emu.mem_protect(base, MAP_CHUNK, UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC); return True
            except: return False
    def on_invalid(emu, access, addr, size, value, user): return map_window(emu, addr)
    try:
        if getattr(uc, "UC_HOOK_MEM_READ_UNMAPPED", None)  is not None: u.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,  on_invalid)
        if getattr(uc, "UC_HOOK_MEM_WRITE_UNMAPPED", None) is not None: u.hook_add(uc.UC_HOOK_MEM_WRITE_UNMAPPED, on_invalid)
        if getattr(uc, "UC_HOOK_MEM_FETCH_UNMAPPED", None) is not None: u.hook_add(uc.UC_HOOK_MEM_FETCH_UNMAPPED, on_invalid)
        if getattr(uc, "UC_HOOK_MEM_INVALID", None)        is not None: u.hook_add(uc.UC_HOOK_MEM_INVALID,        on_invalid)
    except: 
        pass
    return u

GPRS = {"rax":UC_X86_REG_RAX,"rbx":UC_X86_REG_RBX,"rcx":UC_X86_REG_RCX,"rdx":UC_X86_REG_RDX,
        "rsi":UC_X86_REG_RSI,"rdi":UC_X86_REG_RDI,"r8":UC_X86_REG_R8,"r9":UC_X86_REG_R9,
        "r10":UC_X86_REG_R10,"r11":UC_X86_REG_R11,"r12":UC_X86_REG_R12,"r13":UC_X86_REG_R13,
        "r14":UC_X86_REG_R14,"r15":UC_X86_REG_R15}

def emulate_to_tail_jump(u: Uc, start_addr: int, stop_addr: int, zf=None):
    
    # init all registers to zero
    for reg in GPRS.values():
        u.reg_write(reg, 0)

    # Set the ZF flag if provided
    if zf is not None:
        try: u.reg_write(UC_X86_REG_EFLAGS, (1<<6) if zf else 0)
        except:
            try: u.reg_write(UC_X86_REG_RFLAGS, (1<<6) if zf else 0)
            except: pass

    # Set the instruction pointer
    u.reg_write(UC_X86_REG_RIP, start_addr)

    out = {"rax": None}
    # Set up hooks for code execution
    def on_code(emu, address, size, user):
        # print(f"Emulating instruction at {address:#x}, size={size}")
        if address == stop_addr:
            out["rax"] = emu.reg_read(UC_X86_REG_RAX)
            emu.emu_stop()
            

    h = u.hook_add(uc.UC_HOOK_CODE, on_code)
    try:
        u.emu_start(start_addr, 0)
    except Exception as e:
        print(f"Error occurred during emulation: {e}")
    finally:
        u.hook_del(h)

    if out["rax"] is None:
        rip = u.reg_read(UC_X86_REG_RIP)
        print(f"Did not reach jmp rax (RIP={rip:#x})")
    return out["rax"]


def write_rel32_jump(bv, at, target):
    rel = (target - (at + 5)) & 0xFFFFFFFF
    signed = rel if rel < (1<<31) else rel - (1<<32)
    if -0x80000000 <= signed <= 0x7FFFFFFF:
        bv.write(at, b"\xE9" + int(signed).to_bytes(4, "little", signed=True))
        return 5
    else:
        print(f"Rel32 jump from {at:#x} to {target:#x} out of range")
        raise SystemExit()
    

def set_condition_cmp_setcc(bv:BinaryView, il):
    if il.operation != LowLevelILOperation.LLIL_SET_REG:
        return False
    if hasattr(il, "src") and il.src is not None:
        s = il.src
        if s.operation == LowLevelILOperation.LLIL_CMP_NE or s.operation == LowLevelILOperation.LLIL_CMP_E or s.operation == LowLevelILOperation.LLIL_CMP_SLT or s.operation == LowLevelILOperation.LLIL_CMP_SLE or s.operation == LowLevelILOperation.LLIL_CMP_SGT or s.operation == LowLevelILOperation.LLIL_CMP_SGE:
            print(f"Found CMP_NE at {hex(il.address)}")
            bv.set_comment_at(il.address, "CMP_NE detected here")
            return True
    return False

def is_setcc_instruction(bv: BinaryView, addr: int):
    """Check if the instruction at addr is a setcc instruction (sete, setge, setl, etc.)"""
    data = bv.read(addr, 3)
    if len(data) >= 3:
        # setcc instructions: 0x0F 9x xx where 9x varies by condition
        if data[0] == 0x0F and (data[1] & 0xF0) == 0x90:
            # Get the instruction text to identify which setcc it is
            try:
                tokens, length = bv.arch.get_instruction_text(data, addr)
                text = "".join(tok.text for tok in tokens)
                if any(setcc in text.lower() for setcc in ['sete', 'setge', 'setl', 'setne', 'setg', 'setle']):
                    return True                    
            except:
                pass
    return False

def find_setcc_in_block(bv: BinaryView, bb_start: int, bb_end: int):
    """Find the first setcc instruction in the basic block"""
    for addr in range(bb_start, bb_end):
        if is_setcc_instruction(bv, addr):
            # Get the instruction text 
            try:
                data = bv.read(addr, 3)
                tokens, length = bv.arch.get_instruction_text(data, addr)
                text = "".join(tok.text for tok in tokens)
                print(f"Found setcc instruction '{text}' at {hex(addr)}")
                return addr
            except:
                pass
    return None

def write_rel32_jz(bv, at, target):
    rel = (target - (at + 6)) & 0xFFFFFFFF
    signed = rel if rel < (1<<31) else rel - (1<<32)
    if -0x80000000 <= signed <= 0x7FFFFFFF:
        bv.write(at, b"\x0F\x84" + int(signed).to_bytes(4, "little", signed=True))
        return 6
    return 0


bv:BinaryView = bv
funcs = [current_function]
LOOKBACK_INSNS = 5 # excluding call 
llil_func = None

for f in funcs:
    llil_func = f.llil
    if not llil_func:
        continue
    for bb in llil_func:
        items = list(bb) # Get list of BB used to get window
        for idx, il in enumerate(items):
            if not is_call_via_rax(il):
                continue
            
            start = max (0, idx - LOOKBACK_INSNS)
            window = items[start:idx+1]
            # seq_start is used to track where to start NOP'ing from later
            tgt, seq_start = resolve_target_from_window(bv, window, call_addr=il.address)

            # IGNORE if there is no match
            if tgt is None:
                continue  

            annotate_indirect_callsite(bv, il.address, tgt)

            # Begin Patching
            if patch_obfuscated_indirect_call(bv, window, il.address, tgt) == True:
                print( f"Successfully patched indirect call at {hex(il.address)}" )
            else:
                print( f"[ERROR] - Failed to patch indirect call at {hex(il.address)}" )


## Get to the current Basic Block

found_tail_jump = False
tailcall_llil_window = []

bb = next((b for b in current_function.basic_blocks if b.start <= here <= b.end), None)
if bb is not None:
    print(f"Current Basic Block from {hex(bb.start)} to {hex(bb.end)}")
    # get the last instruction in this basic block
    instruction_list = list(bb)
    last_instr = instruction_list[-1]
    instr = last_instr[0] 

    # We want to match['jmp', '     ', 'rax']
    first_token = instr[0].text.lower()
    last_token = instr[2].text.lower()
    if first_token == 'jmp' and last_token == 'rax':
        print("This is an indirect jump via rax")
        found_tail_jump = True

if not found_tail_jump:
    print("No indirect tail jump via rax found in the current basic block.")
    #raise SystemExit()
else:

    
    offset_from_start_of_bb = 0

    # Get current basic block
    instruction_list = []
    bb = next((b for b in current_function.basic_blocks if b.start <= here <= b.end), None)
    #bb = bv.get_basic_blocks_at(here)[0]
    # Collect instructions into instruction list storing address and instruction (containing instruction and length)
    for instr in bb:
        instruction_list.append({ "address" : bb.start + offset_from_start_of_bb, "instruction" : instr })
        offset_from_start_of_bb += instr[1] # Adding length of current instruction

    tailcall_window_start_addr = 0
    tailcall_window_end_addr   = 0

    temp = None

    # Find the earliest instruction of tail call window (first NOP from the back)
    for idx in range(len(instruction_list)-1, -1, -1):
        if instruction_list[idx]["instruction"][0][0].text.lower() == 'nop' :
            tailcall_window_start_addr = instruction_list[idx+1]["address"]
            break
        ## Some BB does not have NOPS, we limit the number of instructions in case of false positives
        if len(instruction_list) - idx > MAX_WINDOW_SIZE: ## Hardcoded to 225 because that was the highest we need after iterative testing
            tailcall_window_start_addr = instruction_list[0]["address"]
            break


    tailcall_window_end_addr = instruction_list[-1]["address"] 
    print(f"Tail call window starts at {hex(tailcall_window_start_addr)}")
    print(f"Tail call window ends at {hex(tailcall_window_end_addr)}")

    ## within this window, we want to get the LLIL instructions
    for i in llil_func.instructions:
        if i.address >= tailcall_window_start_addr and i.address <= tailcall_window_end_addr:
            tailcall_llil_window.append(i)

    ## Now we need to find the actual tail call sequence starting with setcc instruction
    found_conditional_jump_emu_start = False
    found_unconditional_jump_emu_start = False

    # Look for the setcc instruction (sete, setge, etc.) - this should be the real start
    setcc_addr = find_setcc_in_block(bv, bb.start, bb.end)
    if setcc_addr:
        found_conditional_jump_emu_start = True
        tailcall_window_start_addr = setcc_addr
        print(f"Starting emulation from setcc instruction at {hex(setcc_addr)}")

        ## Emulate twice for ZF = 0 and ZF = 1
        print(f"Pre-mapping regions from {hex(setcc_addr)} to {hex(tailcall_window_end_addr)}")
        
        u0 = setup_uc()
        # Ensure the execution region is mapped
        try:
            base_addr = (setcc_addr & ~0xFFF) & ~0xFFFF  # Align to 64KB boundary
            size = 0x20000  # Map 128KB to be safe
            data = bv.read(base_addr, size)
            if data:
                try:
                    u0.mem_map(base_addr, size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
                    u0.mem_write(base_addr, data)
                    print(f"Pre-mapped execution region: {hex(base_addr)} - {hex(base_addr + size)}")
                except:
                    pass
        except Exception as e:
            print(f"Failed to pre-map execution region: {e}")
            
        t0 = emulate_to_tail_jump(u0, setcc_addr, tailcall_window_end_addr, zf=0)
        
        u1 = setup_uc()
        # Ensure the execution region is mapped for second emulator too
        try:
            base_addr = (setcc_addr & ~0xFFF) & ~0xFFFF
            size = 0x20000
            data = bv.read(base_addr, size)
            if data:
                try:
                    u1.mem_map(base_addr, size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
                    u1.mem_write(base_addr, data)
                except:
                    pass
        except:
            pass
            
        t1 = emulate_to_tail_jump(u1, setcc_addr, tailcall_window_end_addr, zf=1)
        print(f"Emulation result ZF=0: {hex(t0) if t0 is not None else 'N/A'}")
        print(f"Emulation result ZF=1: {hex(t1) if t1 is not None else 'N/A'}")
        bv.set_comment_at(tailcall_window_end_addr, f"Emulated tail jump targets: ZF=0->{hex(t0) if t0 is not None else 'N/A'}, ZF=1->{hex(t1) if t1 is not None else 'N/A'}")
        if t0 is not None and bv.get_function_at(t0) is None:
            bv.create_user_function(t0)
        if t1 is not None and bv.get_function_at(t1) is None:
            bv.create_user_function(t1)
    else:
        # Fallback: use the old detection method
        print("No setcc instruction found, using fallback detection")
        for il in tailcall_llil_window:
            if set_condition_cmp_setcc(bv, il):
                found_conditional_jump_emu_start = True
                tailcall_window_start_addr = il.address
                print(f"Found conditional jump emulation start at {hex(il.address)} (FALLBACK)")

                u0 = setup_uc()
                t0 = emulate_to_tail_jump(u0, il.address, tailcall_window_end_addr, zf=0)
                u1 = setup_uc()
                t1 = emulate_to_tail_jump(u1, il.address, tailcall_window_end_addr, zf=1)
                print(f"Emulation result ZF=0: {hex(t0) if t0 is not None else 'N/A'}")
                print(f"Emulation result ZF=1: {hex(t1) if t1 is not None else 'N/A'}")
                bv.set_comment_at(tailcall_window_end_addr, f"Emulated tail jump targets: ZF=0->{hex(t0) if t0 is not None else 'N/A'}, ZF=1->{hex(t1) if t1 is not None else 'N/A'}")
                if t0 is not None and bv.get_function_at(t0) is None:
                    bv.create_user_function(t0)
                if t1 is not None and bv.get_function_at(t1) is None:
                    bv.create_user_function(t1) 
                break



    ## Start patching at the start (tailcall_window_start_addr)
    if found_conditional_jump_emu_start:
        ## We want to NOP the instructions from start of the window
        for il in tailcall_llil_window:
            if il.address < tailcall_window_start_addr:
                continue
            if not bv.convert_to_nop(il.address):
                print( f"[ERROR] - Failed to NOP instruction at {hex(il.address)}" )
                raise SystemExit()
                
        # Patch JZ at the start of emulation window
        if t0 is not None and write_rel32_jz(bv, tailcall_window_start_addr, t0):
            print( f"Successfully patched JZ at {hex(tailcall_window_start_addr)} to {hex(t0)}" )
        else:
            print( f"[ERROR] - Failed to patch JZ at {hex(tailcall_window_start_addr)} (t0={t0})" )
    else:
        print("No load from constant pointer found in tail call window.")
        for il in tailcall_llil_window:
            ## This pattern search (Load_from_const_pointer) exists in both conditional and unconditional.
            ## so do this 0only if we fail to look for conditional (setcc) pattern
            print(f"LLIL Instruction  {il}")
            pointer_value = load_from_const_pointer(bv, il)
            print(f"[DEBUG] -----> Pointer Value: {pointer_value}")
            if pointer_value is not None:
                found_unconditional_jump_emu_start = True
                tailcall_window_start_addr = il.address
                print(f"Found load from constant pointer at {hex(il.address)} with value {hex(pointer_value)}")
                break
            
        if found_conditional_jump_emu_start == False: 
            # only proceed if we did not find conditional jump emulation start
            # Found the location for start of emulation
            emu_start_addr = tailcall_window_start_addr
            emu_stop_addr = tailcall_window_end_addr
            print(f"Emulation will start at {hex(emu_start_addr)}")

            # Setup Unicorn Emulator
            u = setup_uc()
            # Takes in zf to deal with setcc later on
            t = emulate_to_tail_jump(u, emu_start_addr, emu_stop_addr, zf=None)
            print(f"Emulation result: {hex(t) if t is not None else 'N/A'}")
            bv.set_comment_at(emu_stop_addr, f"Emulated tail jump target: {hex(t) if t is not None else 'N/A'}")
            if bv.get_function_at(t) is None and t is not None:
                bv.create_user_function(t) 
            
            ## TODO: Add extra check in case it starts to point somewhere outside of 0x14xxxxxxxx
            
            ## We can NOP all the instruction from the tail call llil window
            for il in tailcall_llil_window:
                if il.address < tailcall_window_start_addr:
                    continue
                if not bv.convert_to_nop(il.address):
                    print( f"[ERROR] - Failed to NOP instruction at {hex(il.address)}" )

            # Finally, we patch in the direct jump
            if write_rel32_jump(bv, tailcall_window_start_addr, t):
                print( f"Successfully patched direct jump at {hex(tailcall_window_start_addr)} to {hex(t)}" )
            else:
                print( f"[ERROR] - Failed to patch direct jump at {hex(tailcall_window_start_addr)}" )
