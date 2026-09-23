# FakePDB — IDA 9.x port

Fork of [Mixaill/FakePDB](https://github.com/Mixaill/FakePDB) (master @ `7beeb88`) updated for
IDA 9.x, targeting 9.4. Older IDA versions should still work: API differences are selected by
feature detection, not version numbers.

## What was actually broken

Most 9.x failures were not the 7.x→9.x API migration itself (upstream had already gated the
obvious removals like `ida_struct` and `get_inf_structure`). They came from three bugs that
combined into a silent failure:

1. **IDA 9.x returns `None` where 7.x returned `""`** — segment classes IDA can't classify,
   names of functions it hasn't displayed yet, unnamed exports. Those became JSON `null`.
2. **The native generator aborts on any JSON `null`** (strict `nlohmann` string conversion, no
   exception handler). On Windows: exit `0xC0000409`. Reproduced here as an indefinite hang.
3. **The plugin discarded the native tool's stderr and exit code**, then printed "done".

Result: "no PDB is ever generated despite the log saying it should be" (upstream #52, #54, #55).

Also fixed:

- `get_ordinal_count()` was called on 9.x but its result never assigned — every 9.x JSON shipped
  an empty `types` list.
- CodeView GUID was read from `imagebase + AddressOfRawData` without checking for an `RSDS`
  signature. For binaries whose debug record isn't memory-mapped (or was overwritten by a packer,
  as in FFXiMain.dll) that read the DOS header as a GUID. Now read from the file and validated.
- PE header offsets assumed PE32; PE32+ debug directory was read from the wrong offset.
- Calling-convention constants looked up by name, so 9.0's removal of `CM_CC_MANUAL` (and reuse
  of its value for `CM_CC_SWIFT`) can't raise `AttributeError` mid-export.
- `bin_search()` return shape and `UA_MAXOP` location handled across versions (signature finder).
- Menu items attached again once the UI is ready (PLUGIN_FIX plugins init before the 9.x menu
  bar may exist).
- IDA no longer left stuck in the "busy" state if an export raises.
- PDB/LIB generation skip the `types` dump, which the native tools never read and which
  dominates JSON size on big databases (#52 reports 178 MB). "Dump info to .json" still includes it.
- **Native:** nulls sanitized at load with a visible warning count; top-level exception handler
  prints the error and exits 2 instead of aborting. Missing JSON is now an error, not an empty PDB.
- **Build:** LLVM pinned to `llvmorg-18.1.8` (upstream cloned `main` HEAD, so builds broke
  whenever LLVM's API moved). CI gained `workflow_dispatch` so a fork can build on demand.

## Install

1. **Delete the old `plugins/fakepdb.py`** if present. The entry point is now
   `fakepdb_plugin.py` (a plugin file named like the package beside it can shadow the package).
2. Copy `src_plugins/ida/fakepdb_plugin.py` and the `src_plugins/ida/fakepdb/` folder into
   `<IDA>/plugins/`.
3. Put the native executables in `<IDA>/plugins/fakepdb/windows_amd64/`:
   `fakepdb_pdb.exe`, `fakepdb_pe.exe`, `fakepdb_coff.exe`. If they're missing, the plugin now
   says so and prints the exact path it looked in.

## Getting the native binaries

Upstream's download link is dead (#51: CI artifacts expired). Build them:

- **GitHub Actions (easiest):** push this repo to your own GitHub fork → Actions tab → CI →
  "Run workflow". Takes roughly an hour (it builds LLVM). Download the `binaries` artifact.
- **Locally:** Visual Studio 2022 + CMake + Ninja, then `./build.ps1` from a Developer PowerShell.

## Using the PDB with FFXiMain.dll

The DLL carries a CodeView debug entry, but its data sits inside the packed `POL1` region and is
not an `RSDS` record. There is no real GUID, so the PDB is written with a zero GUID and **no
debugger will auto-match it**. Load it explicitly:

- **IDA:** File → Load file → PDB file… → pick the `.pdb` (accept the mismatch prompt).
- **WinDbg:** `.sympath+ <dir>` then `.reload /i FFXiMain.dll`.
- **x64dbg:** Symbols tab → right-click the module → load the PDB manually.

## Verification done for this port

No IDA was available, so the Python plugin was exercised against stub `ida_*` modules that
behave like 9.x in the ways the upstream reports describe (no `ida_struct`, no
`get_inf_structure`, `None` from `get_segm_class`/`get_func_name`/`get_entry_name`), populated
with the real `FFETOMain_uncomped.dll` section table and the project's full symbol set.

- Plugin JSON: 484 functions, 471 names, zero nulls, no warnings.
- Native generator built on Linux against LLVM 18.1.3; PDB produced from that JSON.
- `llvm-pdbutil dump -publics`: **955/955 symbols present, 0 at a wrong address**, every
  section:offset round-tripped back to the original virtual address.
- The two null cases from #54/#55 hung the unpatched native tool; the patched tool completes and
  reports the replaced nulls.

What this does **not** cover: anything that only happens inside real IDA 9.4 (menu attachment,
action handlers, the real `func_type_data_t` / `get_tinfo` path, real label iteration). The
first real run in IDA is still the real test; every failure path now prints why.
