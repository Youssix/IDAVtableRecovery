"""
Heuristic vtable analysis for stripped binaries without RTTI.
Scores vtable candidates, infers inheritance from shared prefixes,
and estimates class sizes from constructor patterns.
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_ua
import ida_segment


class VtableCandidate:
    """Scored vtable candidate from heuristic analysis."""

    def __init__(self, ea, func_ptrs):
        self.ea = ea
        self.func_ptrs = func_ptrs
        self.score = 0.0
        self.reasons = []
        self.inferred_name = None
        self.inferred_bases = []
        self.estimated_class_size = 0

    @property
    def size(self):
        return len(self.func_ptrs)

    def __repr__(self):
        name = self.inferred_name or "cls_%X" % self.ea
        return "VtableCandidate(%s, score=%.2f, %d entries)" % (
            name, self.score, self.size
        )


class VtableHeuristics:
    """Heuristic engine for vtable analysis on stripped binaries."""

    # Scoring weights
    WEIGHT_ALIGNED = 0.10
    WEIGHT_CONSECUTIVE_FUNCS = 0.25
    WEIGHT_REASONABLE_COUNT = 0.15
    WEIGHT_CLEAN_BOUNDARY = 0.20
    WEIGHT_XREF_PATTERN = 0.15
    WEIGHT_CONSTRUCTOR_STORE = 0.15

    def __init__(self, scanner):
        """
        Args:
            scanner: VtableScanner instance with section boundaries cached.
        """
        self.scanner = scanner
        self.candidates = []

    def score_vtable_candidate(self, ea, func_ptrs):
        """
        Score a potential vtable region on multiple heuristics.
        Returns a VtableCandidate with score in [0.0, 1.0].
        """
        cand = VtableCandidate(ea, func_ptrs)
        score = 0.0

        # 1. Alignment: vtables are typically 8-byte aligned
        if ea % 8 == 0:
            score += self.WEIGHT_ALIGNED
            cand.reasons.append("8-byte aligned")

        # 2. All entries point to recognized function starts
        func_start_count = 0
        for fptr in func_ptrs:
            func = ida_funcs.get_func(fptr)
            if func and func.start_ea == fptr:
                func_start_count += 1
        func_ratio = func_start_count / len(func_ptrs) if func_ptrs else 0
        entry_score = func_ratio * self.WEIGHT_CONSECUTIVE_FUNCS
        score += entry_score
        if func_ratio > 0.8:
            cand.reasons.append(
                "%d/%d entries are func starts" % (func_start_count, len(func_ptrs))
            )

        # 3. Reasonable entry count (2-200 is typical for real classes)
        count = len(func_ptrs)
        if 2 <= count <= 30:
            score += self.WEIGHT_REASONABLE_COUNT
            cand.reasons.append("reasonable count (%d)" % count)
        elif 30 < count <= 100:
            score += self.WEIGHT_REASONABLE_COUNT * 0.7
            cand.reasons.append("large but plausible count (%d)" % count)
        elif count > 100:
            score += self.WEIGHT_REASONABLE_COUNT * 0.3
            cand.reasons.append("unusually large count (%d)" % count)

        # 4. Clean boundary: preceded by a non-code-pointer or null
        prev_val = ida_bytes.get_qword(ea - 8)
        text_start = self.scanner._text_start or 0
        text_end = self.scanner._text_end or 0
        if prev_val == 0 or not (text_start <= prev_val < text_end):
            score += self.WEIGHT_CLEAN_BOUNDARY
            cand.reasons.append("clean start boundary")

        # 5. Xref pattern: vtable address is referenced (likely stored in ctor)
        xref_count = len(list(idautils.XrefsTo(ea)))
        if xref_count > 0:
            xref_score = min(xref_count / 5.0, 1.0) * self.WEIGHT_XREF_PATTERN
            score += xref_score
            cand.reasons.append("%d xrefs to vtable addr" % xref_count)

        # 6. Constructor store pattern: look for `lea rax, [vtable]; mov [rcx], rax`
        if self._has_constructor_store(ea):
            score += self.WEIGHT_CONSTRUCTOR_STORE
            cand.reasons.append("constructor store pattern found")

        cand.score = min(score, 1.0)
        return cand

    def _has_constructor_store(self, vtable_ea):
        """
        Check if any xref to the vtable address follows the pattern:
          lea reg, [vtable_ea]
          mov [rcx+0], reg       ; or mov [rdi+0] on System V
        This is a strong indicator of a constructor writing the vptr.
        """
        for xref in idautils.XrefsTo(vtable_ea):
            ea = xref.frm
            # Check if it's a LEA instruction
            mnem = idc.print_insn_mnem(ea)
            if mnem != "lea":
                continue

            # Check next instruction is a MOV to [rcx] or [rdi]
            next_ea = idc.next_head(ea)
            if next_ea == idaapi.BADADDR:
                continue

            next_mnem = idc.print_insn_mnem(next_ea)
            if next_mnem != "mov":
                continue

            op0 = idc.print_operand(next_ea, 0)
            # Constructor typically stores to [rcx] (this pointer, MSVC)
            if op0 in ("[rcx]", "[rdi]", "qword ptr [rcx]", "qword ptr [rdi]"):
                return True

        return False

    def match_vtable_patterns(self, candidates):
        """
        Compare vtable layouts to infer inheritance. If vtable A's entries
        are a prefix of vtable B's entries, A is likely a base class of B.

        Returns list of (derived, base) tuples.
        """
        relationships = []

        # Sort by size ascending so we check smaller (base) against larger (derived)
        sorted_cands = sorted(candidates, key=lambda c: c.size)

        for i, possible_base in enumerate(sorted_cands):
            for j in range(i + 1, len(sorted_cands)):
                possible_derived = sorted_cands[j]

                if possible_derived.size <= possible_base.size:
                    continue

                # Check prefix match
                prefix_len = self._shared_prefix_length(
                    possible_base.func_ptrs, possible_derived.func_ptrs
                )

                if prefix_len == possible_base.size:
                    # Full prefix match: strong inheritance signal
                    relationships.append((possible_derived, possible_base))
                    possible_derived.inferred_bases.append(possible_base)
                elif prefix_len >= possible_base.size * 0.8:
                    # Partial match: possible inheritance with overrides
                    # TODO: score by number of overridden slots
                    relationships.append((possible_derived, possible_base))

        idaapi.msg(
            "[VtableHeuristics] Inferred %d inheritance relationships\n"
            % len(relationships)
        )
        return relationships

    def _shared_prefix_length(self, ptrs_a, ptrs_b):
        """Count how many leading entries are identical between two vtables."""
        count = 0
        for a, b in zip(ptrs_a, ptrs_b):
            if a == b:
                count += 1
            else:
                break
        return count

    def estimate_class_size(self, vtable_ea):
        """
        Estimate the class instance size by analyzing constructors that
        reference this vtable. Look for allocation size in operator new
        calls or stack frame size.

        Returns estimated size in bytes, or 0 if unknown.
        """
        for xref in idautils.XrefsTo(vtable_ea):
            func = ida_funcs.get_func(xref.frm)
            if func is None:
                continue

            # Walk backwards from xref to find allocation hint
            size = self._find_alloc_size_in_func(func)
            if size > 0:
                return size

        return 0

    def _find_alloc_size_in_func(self, func):
        """
        Scan a function for calls to operator new(size_t) and extract
        the size argument. Looks for patterns like:
          mov ecx, <size>    ; or mov edi, <size> on System V
          call operator_new
        """
        ea = func.start_ea
        while ea < func.end_ea and ea != idaapi.BADADDR:
            mnem = idc.print_insn_mnem(ea)

            if mnem == "call":
                target_name = idc.print_operand(ea, 0)
                if "new" in target_name.lower() or "??2@" in target_name:
                    # Check previous instruction for size argument
                    prev_ea = idc.prev_head(ea)
                    if prev_ea != idaapi.BADADDR:
                        prev_mnem = idc.print_insn_mnem(prev_ea)
                        if prev_mnem == "mov":
                            op1_type = idc.get_operand_type(prev_ea, 1)
                            if op1_type == idc.o_imm:
                                size = idc.get_operand_value(prev_ea, 1)
                                if 4 <= size <= 0x10000:  # sanity range
                                    return size

            ea = idc.next_head(ea)

        # TODO: also check for stack-allocated objects via sub rsp, <size>
        # TODO: handle placement new patterns
        return 0

    def _assign_heuristic_names(self, candidates):
        """
        Assign placeholder class names based on vtable characteristics.
        Uses constructor function name if available, otherwise generates
        a sequential name.
        """
        class_idx = 0
        for cand in candidates:
            if cand.inferred_name:
                continue

            # Try to derive name from constructor
            for xref in idautils.XrefsTo(cand.ea):
                func = ida_funcs.get_func(xref.frm)
                if func is None:
                    continue
                fname = idc.get_func_name(func.start_ea)
                if fname and not fname.startswith("sub_"):
                    # Use function name as class name hint
                    cand.inferred_name = "cls_%s" % fname
                    break

            if not cand.inferred_name:
                cand.inferred_name = "UnknownClass_%d" % class_idx
                class_idx += 1

    def analyze_stripped(self, vtable_infos):
        """
        Run full heuristic analysis on vtables that lack RTTI.

        Args:
            vtable_infos: list of VtableInfo from VtableScanner
        """
        idaapi.msg(
            "[VtableHeuristics] Analyzing %d stripped vtables...\n"
            % len(vtable_infos)
        )

        scored = []
        for vt in vtable_infos:
            cand = self.score_vtable_candidate(vt.ea, vt.func_ptrs)
            if cand.score >= 0.3:
                scored.append(cand)
                # Update the original VtableInfo with heuristic data
                if not vt.class_name:
                    vt.class_name = cand.inferred_name

                vt_size = self.estimate_class_size(vt.ea)
                if vt_size > 0:
                    cand.estimated_class_size = vt_size

        self._assign_heuristic_names(scored)
        self.match_vtable_patterns(scored)
        self.candidates = scored

        # Update VtableInfo objects with inferred names
        name_map = {c.ea: c.inferred_name for c in scored}
        for vt in vtable_infos:
            if vt.ea in name_map and not vt.class_name:
                vt.class_name = name_map[vt.ea]

        high_conf = [c for c in scored if c.score >= 0.6]
        idaapi.msg(
            "[VtableHeuristics] %d/%d candidates scored >= 0.6\n"
            % (len(high_conf), len(scored))
        )
        return scored
