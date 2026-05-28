# IDA Vtable Recovery

IDA Vtable Recovery is an IDAPython research plugin for discovering C++ vtables,
parsing MSVC RTTI metadata, and exporting reconstructed class information from
x86-64 PE binaries.

The project is designed for reverse engineering and defensive binary analysis.
It helps analysts document class layouts in stripped binaries and reason about
virtual dispatch, inheritance, and object-oriented control flow.

## What is implemented

- `.rdata` scanning for consecutive function-pointer arrays
- vtable candidate filtering against executable `.text` pointers
- MSVC x64 `CompleteObjectLocator` parsing
- `TypeDescriptor`, `ClassHierarchyDescriptor`, and base-class descriptor parsing
- class hierarchy reconstruction when RTTI is available
- heuristic vtable scoring for stripped binaries without RTTI
- constructor-store pattern checks for stronger vtable confidence
- JSON export of recovered vtables and hierarchy data
- C++ header export with reconstructed class skeletons

## Requirements

- IDA Pro 7.x or later
- Python 3 through IDAPython
- x86-64 PE binary loaded in IDA

## Installation

Copy the plugin files to your IDA plugins directory:

```bash
cp ida_vtable_recovery.py <IDA_DIR>/plugins/
cp vtable_heuristics.py <IDA_DIR>/plugins/
cp export_results.py <IDA_DIR>/plugins/
```

Or add this repository directory to your `IDAUSR` path.

## Usage

From IDA, open:

```text
Edit > Plugins > Vtable Recovery
```

Programmatic usage:

```python
from ida_vtable_recovery import VtableScanner
from export_results import export_to_json, export_to_header

scanner = VtableScanner()
scanner.scan()

export_to_json(scanner, "vtables.json")
export_to_header(scanner, "classes.h")
```

## Current status

The plugin is a practical research prototype. RTTI parsing assumes the MSVC x64
ABI, and heuristic recovery is best treated as analyst assistance rather than
ground truth. GCC/Clang RTTI, virtual inheritance edge cases, and split vtables
need more work.

## Responsible use

This project is for reverse engineering, malware-analysis labs, and defensive
binary analysis. It does not modify target binaries or provide exploitation
functionality.

## License

MIT
