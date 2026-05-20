"""
IDA Vtable Recovery Plugin
Automated C++ vtable discovery, RTTI parsing, and class hierarchy reconstruction.
Targets x86-64 PE binaries with MSVC RTTI layout.
"""

import struct
import idaapi
import idautils
import idc
import ida_bytes
import ida_struct
import ida_name
import ida_segment
import ida_nalt
import ida_typeinf
import ida_xref

PLUGIN_NAME = "Vtable Recovery"
PLUGIN_HOTKEY = "Ctrl+Shift+V"
PLUGIN_VERSION = "0.3.0"

# MSVC RTTI signature embedded in CompleteObjectLocator
COL_SIGNATURE_64 = 1  # 64-bit PE


class RTTITypeDescriptor:
    """Parsed _TypeDescriptor from MSVC RTTI."""

    def __init__(self, ea):
        self.ea = ea
        self.vtable_ptr = ida_bytes.get_qword(ea)
        self.spare = ida_bytes.get_qword(ea + 8)
        # Decorated name starts at offset 16, null-terminated
        self.raw_name = idc.get_strlit_contents(ea + 16, -1, idc.STRTYPE_C)
        if self.raw_name:
            self.raw_name = self.raw_name.decode("utf-8", errors="replace")
        else:
            self.raw_name = ""
        self.demangled = self._demangle(self.raw_name)

    def _demangle(self, name):
        if not name:
            return "<unknown>"
        # Strip leading ".?AV" and trailing "@@"
        if name.startswith(".?AV") and name.endswith("@@"):
            return name[4:-2]
        if name.startswith(".?AU") and name.endswith("@@"):
            return name[4:-2]
        return name

    def __repr__(self):
        return "TypeDescriptor(%s @ 0x%x)" % (self.demangled, self.ea)


class RTTIClassHierarchyDescriptor:
    """Parsed _RTTIClassHierarchyDescriptor."""

    def __init__(self, ea, image_base):
        self.ea = ea
        self.signature = ida_bytes.get_dword(ea)
        self.attributes = ida_bytes.get_dword(ea + 4)
        self.num_base_classes = ida_bytes.get_dword(ea + 8)
        # RVA to BaseClassArray
        bca_rva = ida_bytes.get_dword(ea + 12)
        self.base_class_array_ea = image_base + bca_rva
        self.base_classes = []

    @property
    def has_multiple_inheritance(self):
        return (self.attributes & 1) != 0

    @property
    def has_virtual_inheritance(self):
        return (self.attributes & 2) != 0


class RTTIBaseClassDescriptor:
    """Parsed _RTTIBaseClassDescriptor."""

    def __init__(self, ea, image_base):
        self.ea = ea
        td_rva = ida_bytes.get_dword(ea)
        self.type_descriptor_ea = image_base + td_rva
        self.num_contained_bases = ida_bytes.get_dword(ea + 4)
        # PMD structure: mdisp, pdisp, vdisp
        self.mdisp = ida_bytes.get_dword(ea + 8)
        self.pdisp = ida_bytes.get_dword(ea + 12)
        self.vdisp = ida_bytes.get_dword(ea + 16)
        self.attributes = ida_bytes.get_dword(ea + 20)
        chd_rva = ida_bytes.get_dword(ea + 24)
        self.class_hierarchy_ea = image_base + chd_rva


class RTTICompleteObjectLocator:
    """Parsed _RTTICompleteObjectLocator for 64-bit PE."""

    def __init__(self, ea, image_base):
        self.ea = ea
        self.signature = ida_bytes.get_dword(ea)
        self.offset = ida_bytes.get_dword(ea + 4)
        self.cd_offset = ida_bytes.get_dword(ea + 8)
        # RVAs in 64-bit
        td_rva = ida_bytes.get_dword(ea + 12)
        chd_rva = ida_bytes.get_dword(ea + 16)
        self.self_rva = ida_bytes.get_dword(ea + 20)

        self.type_descriptor_ea = image_base + td_rva
        self.class_hierarchy_ea = image_base + chd_rva

    @property
    def is_valid(self):
        return self.signature == COL_SIGNATURE_64


class VtableInfo:
    """Represents a discovered vtable and its associated metadata."""

    def __init__(self, ea, func_ptrs):
        self.ea = ea
        self.func_ptrs = func_ptrs  # list of addresses
        self.class_name = None
        self.col = None  # CompleteObjectLocator
        self.type_desc = None
        self.hierarchy_desc = None
        self.base_classes = []  # list of class names
        self.struct_id = None
        self.is_rtti = False

    @property
    def size(self):
        return len(self.func_ptrs)

    def __repr__(self):
        name = self.class_name or "vtable_0x%x" % self.ea
        return "VtableInfo(%s, %d entries @ 0x%x)" % (name, self.size, self.ea)


class VtableScanner:
    """Core scanner: finds vtables, parses RTTI, creates structs."""

    MIN_VTABLE_ENTRIES = 2
    MAX_VTABLE_ENTRIES = 500  # sanity cap

    def __init__(self):
        self.vtables = []
        self.class_hierarchy = {}  # class_name -> [base_class_names]
        self.image_base = idaapi.get_imagebase()
        self._text_start = None
        self._text_end = None
        self._rdata_start = None
        self._rdata_end = None
        self._resolve_sections()

    def _resolve_sections(self):
        """Cache .text and .rdata section boundaries."""
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            name = ida_segment.get_segm_name(seg)
            if name == ".text":
                self._text_start = seg.start_ea
                self._text_end = seg.end_ea
            elif name == ".rdata":
                self._rdata_start = seg.start_ea
                self._rdata_end = seg.end_ea

        if self._text_start is None:
            # Fallback: use first CODE segment
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg.perm & ida_segment.SFL_CODE:
                    self._text_start = seg.start_ea
                    self._text_end = seg.end_ea
                    break

    def _is_code_ptr(self, ea):
        """Check if ea points into executable code."""
        if self._text_start is None:
            return False
        val = ida_bytes.get_qword(ea)
        if val == 0 or val == idaapi.BADADDR:
            return False
        return self._text_start <= val < self._text_end

    def _is_in_rdata(self, ea):
        """Check if ea is within .rdata bounds."""
        if self._rdata_start is None:
            return False
        return self._rdata_start <= ea < self._rdata_end

    def find_vtables(self):
        """
        Scan .rdata for arrays of consecutive function pointers.
        A vtable candidate is a sequence of qwords where each points
        into .text, preceded by either a non-code-ptr or section start.
        """
        if self._rdata_start is None or self._rdata_end is None:
            idaapi.msg("[%s] ERROR: .rdata section not found\n" % PLUGIN_NAME)
            return []

        idaapi.msg(
            "[%s] Scanning .rdata (0x%x - 0x%x)...\n"
            % (PLUGIN_NAME, self._rdata_start, self._rdata_end)
        )

        candidates = []
        ea = self._rdata_start
        ptr_size = 8  # x86-64

        while ea < self._rdata_end - ptr_size:
            # Look for start of a vtable: current qword is code ptr,
            # and previous qword is NOT a code ptr (or we're at section start)
            if not self._is_code_ptr(ea):
                ea += ptr_size
                continue

            prev_is_code = (
                ea > self._rdata_start and self._is_code_ptr(ea - ptr_size)
            )
            if prev_is_code:
                ea += ptr_size
                continue

            # Found potential vtable start, collect entries
            func_ptrs = []
            scan_ea = ea
            while (
                scan_ea < self._rdata_end
                and self._is_code_ptr(scan_ea)
                and len(func_ptrs) < self.MAX_VTABLE_ENTRIES
            ):
                func_ptrs.append(ida_bytes.get_qword(scan_ea))
                scan_ea += ptr_size

            if len(func_ptrs) >= self.MIN_VTABLE_ENTRIES:
                vt = VtableInfo(ea, func_ptrs)
                candidates.append(vt)

            ea = scan_ea + ptr_size

        idaapi.msg(
            "[%s] Found %d vtable candidates\n" % (PLUGIN_NAME, len(candidates))
        )
        return candidates

    def parse_rtti(self, vtable):
        """
        Read the CompleteObjectLocator at vtable[-1] (the qword immediately
        before the first function pointer). If valid RTTI is found, populate
        vtable metadata.
        """
        col_ptr_ea = vtable.ea - 8
        if not self._is_in_rdata(col_ptr_ea):
            return False

        col_ea = ida_bytes.get_qword(col_ptr_ea)
        if col_ea == 0 or col_ea == idaapi.BADADDR:
            return False

        # The COL pointer should itself be in .rdata
        if not self._is_in_rdata(col_ea):
            return False

        try:
            col = RTTICompleteObjectLocator(col_ea, self.image_base)
        except Exception:
            return False

        if not col.is_valid:
            return False

        # Parse TypeDescriptor
        td = RTTITypeDescriptor(col.type_descriptor_ea)
        if not td.raw_name or not td.raw_name.startswith(".?A"):
            return False

        vtable.col = col
        vtable.type_desc = td
        vtable.class_name = td.demangled
        vtable.is_rtti = True

        # Parse ClassHierarchyDescriptor and base classes
        try:
            chd = RTTIClassHierarchyDescriptor(
                col.class_hierarchy_ea, self.image_base
            )
            vtable.hierarchy_desc = chd
            self._parse_base_classes(vtable, chd)
        except Exception as e:
            idaapi.msg(
                "[%s] WARN: failed to parse CHD for %s: %s\n"
                % (PLUGIN_NAME, vtable.class_name, e)
            )

        return True

    def _parse_base_classes(self, vtable, chd):
        """Walk the BaseClassArray to extract base class names."""
        bases = []
        for i in range(chd.num_base_classes):
            bcd_rva = ida_bytes.get_dword(
                chd.base_class_array_ea + i * 4
            )
            bcd_ea = self.image_base + bcd_rva
            try:
                bcd = RTTIBaseClassDescriptor(bcd_ea, self.image_base)
                td = RTTITypeDescriptor(bcd.type_descriptor_ea)
                bases.append(td.demangled)
            except Exception:
                continue

        # First entry is the class itself, rest are bases
        if len(bases) > 1:
            vtable.base_classes = bases[1:]

    def create_vtable_struct(self, vtable):
        """
        Create an IDA struct for the vtable. Each field is a function
        pointer named after the target function (or vfuncN if unnamed).
        """
        if vtable.class_name:
            struct_name = "vtbl_%s" % vtable.class_name
        else:
            struct_name = "vtbl_%X" % vtable.ea

        # Sanitize struct name for IDA
        struct_name = struct_name.replace("::", "_")
        struct_name = struct_name.replace("<", "_")
        struct_name = struct_name.replace(">", "_")
        struct_name = struct_name.replace(",", "_")
        struct_name = struct_name.replace(" ", "")

        # Delete existing struct if it exists
        sid = ida_struct.get_struc_id(struct_name)
        if sid != idaapi.BADADDR:
            ida_struct.del_struc(ida_struct.get_struc(sid))

        sid = ida_struct.add_struc(idaapi.BADADDR, struct_name, False)
        if sid == idaapi.BADADDR:
            idaapi.msg(
                "[%s] Failed to create struct %s\n" % (PLUGIN_NAME, struct_name)
            )
            return False

        sptr = ida_struct.get_struc(sid)
        ptr_size = 8

        for idx, fptr in enumerate(vtable.func_ptrs):
            # Try to get function name at target
            fname = ida_name.get_name(fptr)
            if fname and not fname.startswith("sub_"):
                field_name = "vfunc_%s" % fname
            else:
                field_name = "vfunc%d" % idx

            # Truncate long names
            if len(field_name) > 120:
                field_name = field_name[:120]

            ida_struct.add_struc_member(
                sptr,
                field_name,
                idx * ptr_size,
                idaapi.FF_QWORD | idaapi.FF_DATA,
                None,
                ptr_size,
            )

        vtable.struct_id = sid

        # Set a name at the vtable address
        vt_label = "%s_instance" % struct_name
        ida_name.set_name(vtable.ea, vt_label, ida_name.SN_NOCHECK)

        idaapi.msg(
            "[%s] Created struct %s (%d entries)\n"
            % (PLUGIN_NAME, struct_name, vtable.size)
        )
        return True

    def rebuild_hierarchy(self):
        """
        Build parent-child class hierarchy from RTTI base class data.
        Populates self.class_hierarchy as {class_name: [base_names]}.
        """
        self.class_hierarchy.clear()

        for vt in self.vtables:
            if not vt.is_rtti or not vt.class_name:
                continue
            if vt.base_classes:
                self.class_hierarchy[vt.class_name] = list(vt.base_classes)
            else:
                self.class_hierarchy[vt.class_name] = []

        idaapi.msg(
            "[%s] Rebuilt hierarchy: %d classes\n"
            % (PLUGIN_NAME, len(self.class_hierarchy))
        )

        # TODO: detect and flag diamond inheritance patterns
        # TODO: handle virtual base class disambiguation
        return self.class_hierarchy

    def apply_to_xrefs(self):
        """
        Find all xrefs to each vtable address and annotate them with
        repeatable comments indicating the class name and vtable offset.
        """
        annotated = 0
        for vt in self.vtables:
            label = vt.class_name or "vtable_0x%x" % vt.ea

            # Annotate xrefs to the vtable base address
            for xref in idautils.XrefsTo(vt.ea):
                comment = "[VTR] %s::vtable" % label
                idc.set_cmt(xref.frm, comment, True)
                annotated += 1

            # Annotate xrefs to individual vtable slots
            for idx, fptr in enumerate(vt.func_ptrs):
                slot_ea = vt.ea + idx * 8
                for xref in idautils.XrefsTo(slot_ea):
                    slot_comment = "[VTR] %s::vfunc[%d]" % (label, idx)
                    idc.set_cmt(xref.frm, slot_comment, True)
                    annotated += 1

        idaapi.msg("[%s] Annotated %d xrefs\n" % (PLUGIN_NAME, annotated))
        return annotated

    def scan(self):
        """Full scan pipeline: find -> parse RTTI -> struct -> hierarchy -> xrefs."""
        idaapi.msg("[%s] v%s starting scan...\n" % (PLUGIN_NAME, PLUGIN_VERSION))

        candidates = self.find_vtables()
        rtti_count = 0

        for vt in candidates:
            if self.parse_rtti(vt):
                rtti_count += 1

        self.vtables = candidates

        idaapi.msg(
            "[%s] %d/%d vtables have RTTI\n"
            % (PLUGIN_NAME, rtti_count, len(candidates))
        )

        # Create structs for all vtables
        for vt in self.vtables:
            self.create_vtable_struct(vt)

        self.rebuild_hierarchy()
        self.apply_to_xrefs()

        # Run heuristic analysis on vtables without RTTI
        no_rtti = [vt for vt in self.vtables if not vt.is_rtti]
        if no_rtti:
            try:
                from vtable_heuristics import VtableHeuristics

                heur = VtableHeuristics(self)
                heur.analyze_stripped(no_rtti)
            except ImportError:
                idaapi.msg(
                    "[%s] vtable_heuristics.py not found, "
                    "skipping heuristic analysis\n" % PLUGIN_NAME
                )

        idaapi.msg(
            "[%s] Scan complete. %d vtables recovered.\n"
            % (PLUGIN_NAME, len(self.vtables))
        )
        return self.vtables


class VtableRecoveryPlugin(idaapi.plugin_t):
    """IDA plugin entry point."""

    flags = idaapi.PLUGIN_UNL
    comment = "Automated C++ vtable discovery and RTTI parsing"
    help = "Scans .rdata for vtables, parses MSVC RTTI, creates structs"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        info = idaapi.get_inf_structure()
        # Only support 64-bit PE files
        if not info.is_64bit():
            idaapi.msg(
                "[%s] Skipping: not a 64-bit binary\n" % PLUGIN_NAME
            )
            return idaapi.PLUGIN_SKIP

        # TODO: add support for 32-bit PE (different COL layout, dword ptrs)
        # TODO: add ELF support with GCC RTTI ABI

        idaapi.msg(
            "[%s] v%s loaded. Hotkey: %s\n"
            % (PLUGIN_NAME, PLUGIN_VERSION, PLUGIN_HOTKEY)
        )
        return idaapi.PLUGIN_OK

    def run(self, arg):
        scanner = VtableScanner()
        scanner.scan()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return VtableRecoveryPlugin()
