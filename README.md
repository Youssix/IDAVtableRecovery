# IDA Vtable Recovery

IDA Pro plugin for automated C++ vtable discovery, RTTI parsing, and class hierarchy reconstruction. Works on x86-64 PE binaries.

Scans `.rdata` sections for arrays of function pointers, parses MSVC RTTI structures when available, and falls back to heuristic analysis for stripped binaries.

## Requirements

- IDA Pro 7.x or later
- Python 3 (IDAPython)
- x86-64 PE binary loaded in IDA

## Installation

Copy the plugin files to your IDA plugins directory:

```
cp ida_vtable_recovery.py   <IDA_DIR>/plugins/
cp vtable_heuristics.py     <IDA_DIR>/plugins/
cp export_results.py        <IDA_DIR>/plugins/
```

Or add the repository directory to your `IDAUSR` path.

## Usage

From IDA: `Edit > Plugins > Vtable Recovery`

The plugin will:

1. Scan `.rdata` for vtable candidates (consecutive code pointers)
2. Parse RTTI `CompleteObjectLocator` at `vtable[-1]` if present
3. Create IDA struct types for each discovered vtable
4. Rebuild class hierarchy from `ClassHierarchyDescriptor` data
5. Annotate xrefs to vtable addresses with class/method comments

### Scripting

```python
from ida_vtable_recovery import VtableScanner

scanner = VtableScanner()
scanner.scan()

# Export results
from export_results import export_to_json, export_to_header
export_to_json(scanner, "vtables.json")
export_to_header(scanner, "classes.h")
```

### Stripped binaries

When RTTI is not available, the plugin uses heuristic analysis to score vtable candidates and infer inheritance relationships from shared vtable prefixes. See `vtable_heuristics.py`.

## Limitations

- RTTI parsing assumes MSVC ABI layout. GCC/Clang RTTI is not yet supported.
- Virtual inheritance with diamond patterns may not reconstruct correctly.
- Vtables split across multiple sections are not detected.

## License

MIT
