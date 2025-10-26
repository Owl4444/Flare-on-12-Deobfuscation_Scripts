# --- config: set these ---
FUNC_ADDR = 0x1402cbc00


TARGET_GLOBALS = {
    0x14047a3ac, 0x14047a3b0, 0x14047a3b4,
}
# -------------

from binaryninja import BinaryView
from binaryninja.enums import DeadStoreElimination





def get_function_by_addr(addr):
    if isinstance(addr, str):
        addr = int(addr, 0)
    f = bv.get_function_at(addr)
    if f: return f
    hits = bv.get_functions_containing(addr)
    return hits[0] if hits else None

def func_contains_addr(f, a):
    if hasattr(f, "address_ranges") and f.address_ranges:
        return any(r.start <= a < r.end for r in f.address_ranges)
    return any(bb.start <= a < bb.end for bb in f.basic_blocks)

def instr_len(a):
    n = bv.get_instruction_length(a)
    return n if n and n > 0 else 1

def collect_code_ref_sites_in_function(f, targets):
    sites = set()
    for g in targets:
        for ref in bv.get_code_refs(g):
            a = getattr(ref, "address", ref)
            if func_contains_addr(f, a):
                sites.add(a)
    return sites

def nop_addresses(f, addrs):
    if not addrs: return 0
    bv.begin_undo_actions()
    for a in sorted(addrs):
        bv.write(a, b"\x90" * instr_len(a))
    bv.commit_undo_actions()
    f.reanalyze()
    return len(addrs)

def dse_fixed_point(f, verbose=True):
    total, rounds = 0, 0
    while True:
        rounds += 1
        flips = 0
        for bb in f.hlil:
            for instr in bb:
                for v in getattr(instr, "vars_written", []):
                    var_obj = getattr(v, "var", v)  # SSAVariable -> Variable
                    try:
                        if var_obj.dead_store_elimination != DeadStoreElimination.AllowDeadStoreElimination:
                            var_obj.dead_store_elimination = DeadStoreElimination.AllowDeadStoreElimination
                            flips += 1
                    except Exception:
                        pass
        f.reanalyze()
        total += flips
        if verbose:
            print(f"[DSE] pass {rounds}: new flips={flips}")
        if flips == 0:
            if verbose:
                print(f"[DSE] {f.name}: converged after {rounds-1} additional pass(es); total flips={total}")
            return total

def run_full_fixed_point(f):
    """Repeat: (NOP code-refs) -> (DSE to fixed point) until both make no progress."""
    outer = 0
    while True:
        outer += 1
        sites = collect_code_ref_sites_in_function(f, TARGET_GLOBALS)
        patched = nop_addresses(f, sites)
        print(f"[NOP] round {outer}: patched {patched} instruction(s)")
        flips = dse_fixed_point(f, verbose=False)
        print(f"[DSE] round {outer}: total flips this round={flips}")
        if  flips ==  0:
            print(f"[DONE] {f.name}: fully converged after {outer} round(s).")
            break


















def last_hlil_instr(bb):
    l = list(bb)
    return l[-1] if l else None


bv:BinaryView = bv

f = current_function
if f is None:
    funcs = bv.get_functions_containing(current_address)
    f = funcs[0] if funcs else None

func = f
print(func)
func = func.hlil
if not func:
    print("HLIL not available for the chosen function.")
    raise SystemExit

for basic_block in func:
    bb:BasicBlock = basic_block
    
    if len(bb.incoming_edges) != 1 or len(bb.outgoing_edges) != 1:
        continue
    
    if bb.instruction_count != 1:
        continue
    
    instr = list(bb)[0]
    

    if instr.operation != HighLevelILOperation.HLIL_ASSIGN and instr.operation != HighLevelILOperation.HLIL_VAR_INIT:
        continue
    print(instr)
    in_edge = bb.incoming_edges[0]

    parent_bb = in_edge.source
    incoming_type = in_edge.type
    print(incoming_type)


    opposite_target = None
    # require parent to have exactly 2 outgoing edges (typical if/else)
    outs = list(parent_bb.outgoing_edges)
    if len(outs) == 2:
        # child_target is the edge that points to this child block
        child_target = bb.start
        # pick the other outgoing edge target
        other = None
        for out in outs:
            if out.target.start != child_target:
                other = out
                break
        if other is None:
            # both outgoing edges point to child? skip
            continue
        opposite_target = other.target.start

        # get the parent's last HLIL instruction (branch site)
        parent_last = last_hlil_instr(parent_bb)
        if parent_last is None:
            continue
        branch_addr = parent_last.address
        try:
            if incoming_type == BranchType.TrueBranch:
                print("INCOMING : TRUE")
                # child reached by TrueBranch -> force False (never take True)
                bv.never_branch(branch_addr)

        except Exception:
            pass
    else:
        continue

run_full_fixed_point(f)
