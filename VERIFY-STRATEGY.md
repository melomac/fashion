# Verifying a Mach-O: what `verify` names, and why

`fashion verify` names what is odd about a Mach-O, one line each, and nothing about a file with nothing to say. This
document is the reasoning behind its rules: what a Mach-O's integrity means, which readers decide it, the rule each
line comes from, the evasion technique each one catches, what was tried and dropped, and the measurements that
decided it. The rules themselves live in `Sources/fashion/MachO/Verifier.swift` and `Signer.swift`; the tests in
`Tests/fashionTests/Commands/VerifierTests.swift` craft every condition and pin every line. Dates and counts below are
from October 2026, macOS 27.2 (26B118) on Apple silicon, with x86_64 files run under Rosetta.

## 1. The question

Two questions drive the design:

1. What does "a Mach-O's integrity" mean, in general, and which strategies check it?
2. Which techniques does malware use to evade static tools, and does `verify` name every one of them?

The answer to the first is five layers (section 3). The answer to the second is a catalogue of thirty techniques
(section 5), each tied to the reader it defeats and the rule that names it (section 4). Most of them survive an
ad-hoc signature: the file is "valid on disk" to `codesign` while carrying hidden data, an inserted library, a desynced
code section or a hidden slice.

## 2. Method: five loaders are the oracle, not any tool

A Mach-O has five readers whose rules matter, and they disagree. Every rule is tied to one of them, read from the
source where Apple publishes it or from the binary where it does not, and tried by running a crafted file:

| Reader | Source read | How it was tried |
|:--|:--|:--|
| Kernel, `parse_machfile` / `load_segment` / `fatfile_validate_fatarches` | xnu-12377.121.6 `bsd/kern/mach_loader.c`, `mach_fat.c`, `kern_exec.c`, `ubc_subr.c` | `posix_spawn` of each file: `errno`, or the signal that killed it |
| dyld, `validSegments` / `validMain` / `validEmbeddedPaths` / `isValidLinkeditLayout` / `FatFile::isValidSlice` | dyld-1378 `common/MachOFile.cpp`, `MachOAnalyzer.cpp`, `MachOLoaded.cpp`, `mach_o/Image.cpp`; the 26B118 dyld's strings for its newer `Header` validator | `dyld_info -validate_only`, and dyld's own abort message at launch |
| Security, `MachO::validateStructure` / `Universal::Universal` / `SecStaticCode::validateExecutable` / `verifySignature` / `CodeDirectory::checkIntegrity` | Security-61901.120.67 `macho++.cpp`, `StaticCode.cpp`, `codedirectory.cpp`, `machorep.cpp`, `reqinterp.cpp`, `legacydevid.cpp` | `codesign -v -v --strict`, and whether `codesign -s -` accepts the file |
| Rosetta, `/usr/libexec/rosetta/runtime` | its own strings (no source) | the `rosetta error:` it prints |
| Gatekeeper and AMFI: syspolicyd's `PolicyScanner`, libmis's `AMFIPathValidator_macos` behind `AMFIExecutionPreflight` | the 26B118 binaries, decompiled (section 7.3) | `spctl -a -t exec`, and running a self-signed or entitled binary |

A sixth reader is every static tool, `otool`, `lipo`, `file`, disassemblers, YARA, and `fashion` itself: where a
tool's parse differs from a loader's, the difference is an evasion.

What the kernel refuses outright, the parser refuses in red before the verifier sees the image (`ParserError`, as
hash mode reports it). What another reader refuses and the parser does not is a line, in that reader's words. What
no reader refuses but a researcher wants named is a line too.

The rules were calibrated against three populations, so that a line is true of the file and not of the toolchain:
every slice under `/usr/bin`, `/bin`, `/sbin`, `/usr/sbin`, `/usr/libexec`, `/usr/lib`, `/System/Library/Frameworks`,
`/System/Library/PrivateFrameworks` and `/System/Applications` (4,216 slices); `/Applications`, Homebrew and
`/usr/local` (27,967 slices); and a malware corpus of 3,080,217 files. Section 7 has the numbers.

## 3. What integrity means: five layers

The strategies stack. Each layer answers a different question and reads a different amount of the file.

1. **Would it load?** The loaders' own rules: header, load-command table, segments, fat table. The parser already
   refuses the kernel's hard rules in red. Everything a loader refuses but the parser accepts is a line, in that
   loader's words. Headers only.
2. **Does it agree with itself?** Fields that describe the same bytes twice must agree: `ncmds` and `sizeofcmds`,
   the fat table and each slice's header, a section's address and its file offset, a table's range and the segment it
   lives in, an entry point and the segment it lands in. A disagreement is the definition of a parser differential:
   one reader believes one field, another the other. Headers only.
3. **Is it all accounted for?** Every byte of the file either belongs to a segment's mapped content, a table a load
   command references, the signature, or padding the linker wrote as zeros. Bytes nobody references that are not zero
   are a payload or a watermark: the header pad, section and segment tails, the gaps between segments, between fat
   slices, inside `__LINKEDIT` between tables, and past the image. None of these is non-zero in any of the OS's 4,216
   slices. Reads the padding only.
4. **Does the signature vouch for it, and who signed?** The code directory's slots against the pages
   (`validateExecutable`), its special slots against the blobs they seal (requirements, entitlements, DER
   entitlements), the code limit against where the signature starts, and what the signature says of itself: ad hoc,
   linker signed, entitled to opt out of hardening. Reads the signed extent once. Then the signer: the CMS blob
   verified over the directory as Security verifies it, and the certificate chain classed as Gatekeeper and AMFI
   class it (section 7.3).
5. **Is the identity stable?** What `fashion` hashes for: the digests that collapse the copies an adversary makes.
   The techniques of layer 3 are exactly the free space an adversary has to make one sample many without changing
   what loads: a canonical form would zero it (section 8).

## 4. The rules, by the reader that enforces them

Each rule with its authority and message, and what happened when a crafted file carrying the condition ran
("Launch"). Rules marked "live dyld" come from the strings of the dyld in the 26B118 shared cache, whose `Header`
validator the published dyld-1378 sources do not show yet (section 7.2). Rules marked "not named" were tried and
left out, with the reason.

### Universal files

| Rule | Authority | Launch |
|:--|:--|:--|
| An arm64 slice hidden past the table: `nfat_arch` entries plus one, when that one names arm64 (`lipo -hideARM64`), past a count of none too; the line says who finds it, and one whose range does not hold is refused red, as dyld refuses the file | dyld `forEachSlice` "Look for one more slice", an exact `arm64` entry below 16 entries, which `Universal::valid` checks like the others; Security `Universal::Universal` "Hack alert" 15001604, `mArchCount++`, any arm64 subtype; the kernel reads `nfat_arch` only | ran: the kernel picked x86_64; dyld and codesign see two slices, `lipo -archs` prints both, `file` prints one |
| Two slices of one `cputype`/`cpusubtype` | kernel `fatfile_validate_fatarches` → `LOAD_BADMACHO` | `errno 88 Malformed Mach-o file` |
| The table's `cputype`/`cpusubtype` not the slice header's | dyld `isValidSlice` "cpu type in slice does not match fat header"; kernel `exec_mach_imgact` `EBADARCH` | `errno 86 Bad CPU type` |
| A slice not aligned to its own page: 16 KiB for arm64, 4 KiB otherwise | dyld `isValidSlice` "slice is not page aligned" (`uses16KPages`) | killed (unsigned arm64) |
| Padding between the table and slices, or between slices, not zero | Security `Universal::Universal` "non-zero gap byte", `mSuspicious` | `codesign -s -` refuses the file; the kernel does not look |
| `FAT_MAGIC_64` | kernel `fatfile_validate_fatarches` `magic != FAT_MAGIC` → `LOAD_FAILURE`; Security treats it as a generic file | `errno 8 Exec format error` |
| A slice that is itself universal | kernel `parse_machfile` magic | `errno 8` |
| More than 100 (Security) / 204 (dyld) slices; `fashion` stops at dyld's `kMaxSliceCount` 16: past it, a file whose entries hold is named with its count, neither hashed nor verified as slices, where a Java class (0xCAFEBABE too) says nothing | kernel `fatfile_validate_fatarches` reads as many entries as its page holds, 204 or 818, and runs one | |

### Load-command table

| Rule | Authority | Launch |
|:--|:--|:--|
| `ncmds` fewer than the commands `sizeofcmds` holds: the loaders read `ncmds`, Security walks `sizeofcmds`; the loaders' rules, the parser's kernel range rule among them, run over the `ncmds` commands alone, so a segment hidden past them lying past the file is named here, not refused | kernel and dyld walk `ncmds`; Security `MachOBase::nextCommand` walks the table | signed after hiding its `LC_CODE_SIGNATURE`: "valid on disk" to codesign, Rosetta "sizeofcmds is incorrect"; native dyld would run it unsigned |
| `ncmds` more than the table holds | dyld "extends past sizeofcmds"; kernel `LOAD_BADMACHO` | killed |
| Bytes inside `sizeofcmds` past the last command that hold no command: the parser takes the table when its `ncmds` commands fit, verify names the tail | kernel and dyld walk `ncmds` commands; Security `MachOBase::nextCommand` is lazy and `MachO::MachO` stops at `__LINKEDIT`/`LC_SYMTAB`, so `codesign --verify` passes; `codesign_allocate` "inconsistent sizeofcmds field", Rosetta "sizeofcmds is incorrect" | ran (arm64, code slot 0 refreshed); dlopen loaded a dylib; Rosetta refused |
| A `cmdsize` not a multiple of 4, not pointer sized on 64-bit | dyld `forEachLoadCommand` "not multiple of 4"; live dyld "cmdsize is not pointer sized" | ran; `dyld_info` flags it, launch did not |
| `LC_SEGMENT` in a 64-bit image, `LC_SEGMENT_64` in a 32-bit one | kernel "LC_SEGMENT command for the wrong ABI" `LOAD_BADMACHO` | killed |
| Two of `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_DYLD_INFO`, `LC_DYLD_EXPORTS_TRIE`, `LC_DYLD_CHAINED_FIXUPS`, `LC_SEGMENT_SPLIT_INFO`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, `LC_CODE_SIGNATURE`, `LC_UUID`, `LC_VERSION_MIN_*`, `LC_ENCRYPTION_INFO(_64)` | dyld `getLinkEditLoadCommands` "multiple … load commands"; Rosetta "multiple LC_LOAD_SIGNATURE / LC_UUID"; the kernel takes the first signature blob, `codesign --remove-signature` the last | two signatures: Rosetta refused; two symtabs: ran |
| Two of `LC_BUILD_VERSION`/`LC_VERSION_MIN_*`, `LC_LOAD_DYLINKER`, `LC_MAIN`/`LC_UNIXTHREAD`, in an executable | kernel `found_version_cmd`, `dlp`, `thread_count` → `LOAD_BADMACHO`/`LOAD_FAILURE`; dyld "only one LC_MAIN or LC_UNIXTHREAD"; not named outside executables: zippered dylibs carry two `LC_BUILD_VERSION`, and the kernel's rule is for the executable it loads | `LC_MAIN` + `LC_UNIXTHREAD`: killed |
| Two of `LC_ID_DYLIB`, `LC_ROUTINES`, `LC_ATOM_INFO`, `LC_FUNCTION_VARIANTS`, `LC_FUNCTION_VARIANT_FIXUPS`, `LC_TARGET_TRIPLE` | live dyld "multiple LC_… load commands found" | |
| An `lc_str` starting inside its command's fixed fields, a dylib command's 24 bytes, the others' 12: named with the offset | live dyld "string start offset too small" | |
| More than 64 MiB of load commands | this tool's own limit, as the symbol names': refused red before the table is read; no loader has one | |
| A superblob declaring more than 64 MiB | this tool's own limit, as the load commands': refused red before it is read, in hash mode as in `verify`; Security reads what the length says and the kernel maps what `LC_CODE_SIGNATURE` says, a sparse file costing either the length in memory | |
| `LC_DYSYMTAB` without `LC_SYMTAB`; `LC_DYLD_INFO` with `LC_DYLD_CHAINED_FIXUPS` | dyld | ran |
| `LC_DYLD_INFO` beside `LC_DYLD_INFO_ONLY`, `LC_ROUTINES` beside `LC_ROUTINES_64` | dyld `validStructureLoadCommands` counts each pair as one command: "multiple LC_DYLD_INFO load commands found" | |
| No `LC_UUID` | dyld `validLinkedit` "missing LC_UUID" (SDK ≥ 14) | dyld aborted |
| No `LC_LOAD_DYLIB` at all | dyld "must link with at least libSystem.dylib" (SDK ≥ 13) | dyld aborted |
| `LC_ID_DYLIB` in a non-dylib; `MH_DYLIB` without one | dyld `validEmbeddedPaths` | dyld aborted |
| A dylib or rpath name not NUL-terminated inside its command | dyld "string extends beyond end of load command" | dyld aborted |
| `LC_LOAD_DYLINKER` naming anything but `/usr/lib/dyld` | kernel `load_dylinker` `DEFAULT_DYLD_PATH` → `LOAD_BADMACHO` on release kernels | killed |
| `MH_DYLDLINK` without `LC_LOAD_DYLINKER` | kernel `needs_dynlinker && !dlp` | |
| `LC_ENCRYPTION_INFO(_64)` with `cryptid` ≠ 0; the 32-bit one in a 64-bit image | kernel `set_code_unprotect`; dyld bitness check | killed |
| `LC_DYLD_ENVIRONMENT`, and what it sets | dyld honors `DYLD_INSERT_LIBRARIES` from the image itself; a value longer than 128 bytes is cut to 80 with its length (Apple's BlastDoor services set `DYLD_DLSYM_RESULT` to 24 KB) | dyld tried to load `/tmp/evil.dylib`; signed ad hoc, "valid on disk" |
| An executable with no `MH_PIE`: arm64 and armv7k | kernel `pie_required` → `LOAD_FAILURE`; x86_64 runs without ASLR | arm64: killed; x86_64: ran |
| `MH_EXECUTE` without `MH_DYLDLINK`: static | kernel: x86_64 only on release kernels; dyld `isStaticExecutable` relaxes its own checks | ran (x86_64) |
| A filetype no loader knows | dyld "unknown mach-o filetype" | |

### Segments and sections

| Rule | Authority | Launch |
|:--|:--|:--|
| A segment's file offset not page aligned, even an empty one; the page is the platform's as `MachORep::pageSize` has it, 4 KiB for arm64 on iOS before 16 and tvOS | kernel `load_segment` "can't mmap() it if it's not page-aligned" `LOAD_BADMACHO` | killed |
| A segment command's size not `nsects` sections exactly | dyld "does not match nsects"; kernel "sections would fit" | |
| Protection bits beyond rwx; `initprot` outside `maxprot` | dyld "invalid bits set"; kernel `vm_map_enter` | |
| Two segments of one name; an empty name | dyld (cache builder); `__LINKEDIT` twice: Rosetta "multiple __LINKEDIT segments" | ran |
| More than 255 segments; `sizeofcmds` past `__TEXT` | dyld `validSemanticsSegments` "too many segments %llu (max 255)", "load commands exceed length of __TEXT segment" | |
| `__DATA_CONST` not rw- in an image dyld manages | live dyld `validSemanticsSingleSegment` "__DATA_CONST segment permissions is not 'rw-'", gated by `isDyldManaged` alone | |
| A section's address range outside its segment | dyld `validSegments` "end address is beyond containing segment" | dyld aborted |
| A section's file offset not where its address lays it (`offset ≠ fileoff + addr − vmaddr`), or laid past 2^64 by a segment that maps most of the address space | no loader maps by section: static tools read the section's `offset`, the loader maps the segment; Rosetta translates from the section | crashed under Rosetta, "valid on disk" when signed; would run natively |
| Segments overlapping in the file or in memory, however many: one pass in the order of their starts, each against the one reaching furthest before it | dyld `validSegments`; a crafted table of thousands of segments would cost their square | |
| A section's `offset + size` past the file, overlapping sections | static tools | |
| A zero-fill section with a file offset; a section with an empty name | live dyld `validSemanticsSingleSegment` "has a zero-fill section type, but offset field is not zero", "has an empty section name": images dyld manages, built against the fall-2026 SDK or later (`Policy`, epoch 0x4F29), on the path that maps from disk | |
| A section's address not aligned to its align field; a section with content and no file offset; two sections sharing addresses; in a segment that is mapped (Go's `__DWARF` has no vmsize) | live dyld `Header::validSections` "align field does not match address", "has offset=0 but is not a zero-fill section type", "start address overlaps previous section" | |
| A section's align field past 2^15 | live dyld "too large for VM to support"; not named: Tor Browser's and numpy's dylibs declare 2^16 and run | |
| `__DATA_CONST` without `SG_READ_ONLY` | live dyld "__DATA_CONST segment missing SG_READ_ONLY flag"; not named: 177 of Apple's own slices lack it (`libccid`, the toolchain's Swift libraries), so dyld does not refuse it | |
| `__TEXT` without sections | research: packers, crafted stubs | |
| `__TEXT`'s `vmsize` more than a page past its `filesize` | research: room to unpack into (UPX) | killed only because it overlapped `__DATA_CONST` |
| A segment both writable and executable; an executable segment not `__TEXT` (nor `__TEXT_EXEC` in a kext) | kernel on arm64 "curprot cannot be write+execute"; research on x86_64: Keydnap's `__TEXT` is rwx; the i386 linker's `__IMPORT` is rwx by design and not named | ran, unsigned x86_64 |
| A segment or section name with bytes after its NUL, or not printable ASCII (`__TEXT\0junk`, a Cyrillic е in `__text`); shown quoted | `strncmp` readers and prefix readers disagree; lookalikes | ran, "valid on disk" when signed |
| `mach_header_64.reserved` not zero | no reader | ran |
| A segment flagged `SG_PROTECTED_VERSION_1`: the kernel decrypts its pages past the first three as it maps them (`unprotect_dsmos_segment`, Apple's protection of a few 10.4 to 10.6 binaries), so a third party's code reads encrypted on disk | kernel `load_segment`; static tools read the file | |

### Entry point

| Rule | Authority | Launch |
|:--|:--|:--|
| `LC_MAIN`: `__TEXT`'s address + `entryoff` in a segment that is not executable, or in none | dyld `validMain` "LC_MAIN points to non-executable segment" | `SIGBUS` at the jump; "valid on disk" when signed |
| An entry in `__TEXT` but in no section, or in one that holds no code (`__cstring`, `__const`, a protector's own); a stub section is an entry too, which an app extension enters through for its imported `_NSExtensionMain` (496 of the OS's arm64e slices), as is GCC's `__text_startup` | research | |
| `LC_UNIXTHREAD`: the pc register (`rip` index 16, `eip` 10, arm `pc` 15, arm64 `pc` 32) in a non-executable segment, or a flavor the arch does not have; every thread state in the command walked, each a flavor `thread_entrypoint` takes (x86_64: its state and `x86_THREAD_FULL_STATE64`), the last one's pc the entry where dyld reads the first, which is named when there are several; the first must be the flavor dyld's `entryAddrFromThreadCmd` takes, x86_64's thread state and not its full one, or dyld finds no entry | dyld `entryAddrFromThreadCmd`; kernel `load_threadentry` | `SIGBUS` |

### `__LINKEDIT`

| Rule | Authority | Launch |
|:--|:--|:--|
| A table (`LC_SYMTAB`, `LC_DYSYMTAB`, `LC_DYLD_INFO`, exports trie, chained fixups, function starts, data in code, split info, atom info, signature) outside `__LINKEDIT`, or two overlapping | dyld `Image::isValidLinkeditLayout` "LINKEDIT content extends beyond end of segment", "LINKEDIT overlap" | ran: not enforced at launch for a main executable |
| `__LINKEDIT` not ending the image; `LC_SYMTAB` strings not ending it in a ppc image | Security `validateStructure` "invalid structure" (strict) | |
| Bytes inside `__LINKEDIT` no table references, not zero | research: a payload signed over when signed after | ran; "valid on disk" when signed |

### Padding

| Rule | Authority | Launch |
|:--|:--|:--|
| Bytes no section covers that are not zero: the header pad, a segment's padding after its last section; not a gap shorter than the alignment of the section that follows, which an older ld64 fills with no-ops on x86_64 (862 Python extension modules) | research: a payload, free polymorphism | ran; "valid on disk" when signed |
| Bytes between two segments that are not zero | research | ran |
| Bytes appended past the image's end | research: a new hash per copy, polyglots; `--exact` undoes it | ran |
| A `__LINKEDIT` vmsize rounded as a signature rounds it, on an image without a signature; not named of a stripped 64-bit image that records no linker (`LC_VERSION_MIN_MACOSX`, macOS 10.13 and earlier), whose `strip` may have rounded to 16 KiB itself (cctools 1010, Xcode 15.3) | research: a signature came out, which `codesign --remove-signature` leaves so | ran (x86_64) |
| UPX, as is, by a modified UPX with its marker, or signed after packing; a pack header found that does not hold, which `unpack` refuses | research; `--unpack` undoes it | ran |

### Code signature

| Rule | Authority | Launch |
|:--|:--|:--|
| An arm64 image without a signature | kernel `cs_process_global_enforcement` → `LOAD_FAILURE`; a fresh unsigned build is the one thing the toolchain makes that says so | killed |
| A code directory whose slots do not hash the code: which page | Security `validateExecutable` `kSecCFErrorInvalidPage`; the kernel kills on that page | `SIGSEGV`, or killed |
| Code limit short of the signature's offset: pages before the signature left unsigned | kernel `csb_end_offset`: segments past it refused, pages inside a segment past it unsigned; Security: `codesign -v` says "invalid or unsupported format"; dyld "code signature does not cover entire file up to signature" | ran (x86_64 unenforced) |
| `LC_CODE_SIGNATURE`'s `datasize` past its superblob's length | not named: Apple's own arm64e slices keep a stale signature's hashes there, where the x86_64 slice's larger signature sized the range (272 OS slices) | |
| `LC_CODE_SIGNATURE`'s `datasize` not a multiple of 16 | Security `assure_signature_space` "signature size not a multiple of 16"; not named: ld64's linker signatures have any size (1,169 Homebrew slices) | |
| A special slot not hashing its blob: requirements, entitlements, DER entitlements; not Info.plist, whose slot seals a bundle's plist as often as the `__info_plist` section's, and which a signer may leave at zero (Apple's own `fairplayd`) | kernel `csblob_find_special_slot_blob` for entitlements and DER (`EBADEXEC`); Security `validateComponent` for all | killed |
| A blob under another magic than its slot's: the CMS wrapper (0xfade0b01), the entitlements (0xfade7171), their DER form (0xfade7172); what such entitlements say is granted to nothing | Security `EmbeddedSignatureBlob::blobData` throws errSecCSSignatureInvalid for the CMS; kernel `cs_validate_csblob` refuses the signature (EBADEXEC) for the entitlements, codesign warns "invalid entitlements blob" | |
| Two code directories of one hash type: refused red, as hash mode refuses it | kernel "multiple hash=%d CodeDirectories; rejecting"; Security `loadCodeDirectories` throws `errSecCSSignatureInvalid` (26B118), codesign "invalid or unsupported format for signature" | |
| A page size other than 4 KiB or 16 KiB | kernel `cs_validate_codedirectory` "disallowing unsupported code signature page shift" | |
| A code directory shorter than 0x70 bytes, under another magic than 0xfade0c02, with an identifier offset of 0 or past its end, or (version 0x20600 on, linkage hash type set) a linkage past its end: Security loads it, the kernel refuses the signature whole | kernel `cs_validate_codedirectory` (26B118): `length < 0x70 || magic != 0xfade0c02`, identOffset non-zero and below the length, linkage bounds; Security `CodeDirectory::validateBlob` checks none of them, `codesign -vvv --strict` says "valid on disk" | killed (arm64) |
| The index as the kernel walks it: a directory past a gap in the alternates, two of one hash type wherever they lie, two entries of an entitlements slot, an entry at offset 0 | kernel `cs_validate_csblob` validates every entry by type, `F_ADDFILESIGS_RETURN` refuses with EBADEXEC; Security `loadCodeDirectories` stops at the first alternate missing, `SuperBlob::find` takes the first entry, offset 0 tolerated | killed (arm64) |
| The signer's hash-agility attributes not binding every directory the signature holds: the cdhashes plist (1.2.840.113635.100.9.1) other than each loaded directory's cdhash truncated to 20 bytes in hash-type order, or the v2 attribute (.9.2) other than one full cdhash per loaded directory by its digest algorithm | Security `validateDirectory` (verifySignature inlined, 26B118): errSecCSSignatureFailed on either; a signer that wrote neither binds nothing, codesign takes it | codesign "invalid signature" (a self-signed CMS whose attributes name a directory changed since) |
| Code directories that disagree on their code limit or page size: every directory's slots are checked over the pages the lowest hash type's directory cuts, as Security cuts them, and the disagreement named | Security `validateExecutableSlots` (inlined in `staticValidateCore`, 26B118) takes codeLimit and pageSize from the first directory of its map, the lowest hash type, and compares each directory's slot at the same index; the kernel `cs_validate_page` cuts by the directory it ranks first | codesign "valid on disk" where the other directory's own pages would not hash |
| A SHA-512 code directory | Security `hashPriorities` [5, 4, 2, 3, 1]: ranked first, the flags, team and CDHash read by it, as hash mode orders the directories; kernel `cs_validate_codedirectory` knows no hash type 5 and refuses the signature; codesign writes none (`--digest-algorithm` takes no sha512) | |
| A scattered code directory | Security only; not checked, named | |
| Ad hoc (`CS_ADHOC`), linker signed (`CS_LINKER_SIGNED`), no hardened runtime | not named: every arm64 build has one, and Apple's own platform binaries lack the hardened-runtime flag | |
| A CMS blob missing behind a directory not flagged ad hoc | identity: an `ldid`-style signature | |
| A CMS blob behind a directory flagged ad hoc | Security `verifySignature` returns before reading it: "ad-hoc signed code is considered validly signed by definition" | |
| The ad-hoc flag and the team identifier read from the best code directory, the kernel's choice, where the CMS blob is verified over slot 0: two directories that disagree are read as Security reads them | Security `codeDirectory()` picks by `hashPriorities`, `teamID()` reads it, the detached content is the slot-0 blob (26B118 `validateDirectory`) | |
| Entitlements that opt out of hardening: `com.apple.security.cs.allow-unsigned-executable-memory`, `allow-jit`, `allow-dyld-environment-variables`, `disable-library-validation`, `disable-executable-page-protection`, `get-task-allow`, `cs.debugger` | identity | ran, "valid on disk" |
| The DER entitlements (slot 7) decoded as AMFI reads them, the entitlement verdicts read from them, and a disagreement with the XML form named by key; what AMFI refuses the code for named, with no verdict: a root other than the version 1 wrapper (application 16, INTEGER 1, a context-16 dictionary, nothing after it) or a version 0 SET, keys not strictly ascending under version 1, a pair that is not a string key and one value, a value other than BOOLEAN, INTEGER, UTF8String, SEQUENCE or a dictionary under the root's tag, nesting past 12 levels; bytes past the wrapper or the version 0 dictionary are not read | CoreEntitlements `CEValidateWithOptions` and `recursivelyValidateEntitlements` (26B118 kernelcache), run by AMFI's `CEContextInitWithTypeLegacy` with options admitting OCTET STRING, NumericString, UTCTime and dictionaries under other tags, which exec refuses all the same (arm64, macOS 27.2: killed); the kernel's `cs_validate_csblob` checks the blob's magic alone; `codesign -d --entitlements -` runs the validator under other options and decodes a nested SET AMFI kills | killed (arm64), codesign "could not validate entitlement data" |

### The signer

| Rule | Authority | Launch |
|:--|:--|:--|
| The CMS signature not verifying over the code directory, or no signer in it | Security `verifySignature` → `errSecCSSignatureFailed`; the kernel asks amfid, which refuses | killed on arm64 |
| A CMS blob with other than one signer | Security `verifySignature` (26B118): "CMS has %zu signers, expected exactly one", errSecCSSignatureFailed; the kernel asks amfid, which refuses | codesign "invalid signature" (the same signer twice) |
| A chain expired or not yet valid at the date the signer claims, the secure timestamp's, else the signing time: tolerated, as Security tries again with expiry allowed only without a secure timestamp; refused under the directory's CS_ENFORCE_EXPIRATION flag (`codesign -o expires`) | Security `validateDirectory`: a second evaluation with CSSM_TP_ACTION_ALLOW_EXPIRED when the first fails with CERT_EXPIRED or CERT_NOT_VALID_YET and mSigningTimestamp is 0, then CSSMERR_TP_CERT_EXPIRED under kSecCodeSignatureEnforceExpiration (0x400) | codesign "valid on disk" for the tolerated one, "invalid signature" for the flagged one |
| A secure timestamp whose chain ends outside Apple's roots behind a signer anchored at Apple | Security `validateDirectory`: isAppleCA on the signer's anchor requires isAppleCA on the timestamp's, else CSSMERR_TP_NOT_TRUSTED "timestamp policy verification failed"; the decoder verifies the token against the system's anchors before any of it, so no test reaches the rule offline (a Developer ID signature with a DigiCert token did, in the second review) | |
| A chain that ends outside Apple's roots (self-signed, another CA) | Security builds the chain with `CSSM_TP_ACTION_IMPLICIT_ANCHORS` and no anchors: `codesign -v` passes, the kernel runs it; syspolicyd's `PolicyScanner` matches no requirement: `spctl` "rejected" | ran (arm64, a self-signed Developer ID-shaped leaf) |
| A development or App Store submission leaf (`6.1.12`, `6.1.2`, `6.1.7`, `6.1.4`) under Apple's root | AMFI `developerRequirement` accepts it; Gatekeeper has no requirement for it: "rejected" | ran |
| An Apple-issued leaf for something other than code (installer certificates, others) | neither AMFI's `basicRequirement` nor Gatekeeper | |
| A Developer ID signature meeting `legacy`: account created before 2019-04-07 (extension `6.1.33`, when present), secure timestamp before 2019-06-01; the timestamp token verified here with no network, its imprint over the signature and its chain to the system's anchors, where trustd may fetch the authority's issuer | `legacydevid.cpp` `meetsDeveloperIDLegacyAllowedPolicy`: Gatekeeper runs it without a ticket | |
| The code directory's team identifier not the leaf's OU, behind a developer certificate | Security `verifySignature` → `errSecCSBadTeamIdentifier`, only when `isAppleDeveloperCert` (WWDR development, Developer ID, distribution leaves) | |
| Entitlements outside AMFI's `unrestrictedEntitlements` (`com.apple.security.*`, `com.apple.private.signing-identifier`, `com.apple.developer.hardened-process*`) and `softRestrictedEntitlements` (`com.apple.application-identifier`, `com.apple.security.application-groups*`): all of them under an ad-hoc, absent, failed or outside signature; only `com.apple.private.*` under a developer's certificate, where a provisioning profile grants the rest; none under Apple's own or the App Store's, whose apps Apple provisions itself | libmis `validateWithError:`: validated against `anchor apple`, then the bundle's provisioning profile; refused otherwise (`-424` with no chain at all) | killed |

## 5. Evasion techniques, and the reader each one defeats

Each technique as an adversary uses it and the reader it defeats. `verify` names every one. "Signed" means the
ad-hoc signed variant is "valid on disk" to `codesign`. The tests craft each in the group the verifier names it from:
the table, segments and sections, the entry point, what the image links, the padding, the signature, the signer, the
universal file.

| # | Technique | Defeats |
|--:|:--|:--|
| E1 | Append bytes after the image (new hash per copy, polyglots) | hash lists; `--exact` undoes it |
| E2 | Sign again with another identity | hash lists; `--unsign` undoes it, and its residue is named |
| E3 | UPX, a modified UPX (marker, XOR'd blocks), signed after packing | hash lists, YARA; `--unpack` undoes it |
| E4 | Hide an arm64 slice past the fat table | the kernel, `file`, every scanner reading `nfat_arch`; dyld loads it |
| E5 | Two slices of one arch: a scanner hashes one, a tool extracts the other | scanners that take the first match |
| E6 | Label a slice with another cputype in the table | scanners that trust the table; `file` says arm64e of an arm64 |
| E7 | Payload in fat padding, "headiting": bytes written into the free space after the fat table, which the kernel skips and the digest keeps | scanners that hash slices |
| E8 | A fat64 (`codesign` signs it as a generic file, the kernel runs nothing) | signature checks |
| E9 | `ncmds` short of the table: hide `LC_CODE_SIGNATURE` or any command from the loaders, keep it for Security | parsers that walk `ncmds` vs `sizeofcmds` |
| E10 | Two `LC_CODE_SIGNATURE`: the kernel validates the first, `codesign --remove-signature` strips the last | signature removers, hash-after-unsign |
| E11 | Section `offset` desynced from its address: disassemblers show other code than what runs | IDA, otool, YARA on sections, symhash-like code hashes |
| E12 | Payload in the header pad, section tails, between segments | hash lists (free polymorphism), hex-scanning |
| E13 | Payload inside `__LINKEDIT` between tables, signed over | everything that trusts a valid signature |
| E14 | Entry outside `__TEXT`, by `LC_MAIN` or by `LC_UNIXTHREAD`'s pc | disassemblers starting at `__text` |
| E15 | `LC_DYLD_ENVIRONMENT` inserting a library | dylib-hijack reviews |
| E16 | No `MH_PIE`, executable stack, flat namespace | exploit mitigations |
| E17 | Static executable, a dylinker of its own | hooking-based EDR |
| E18 | Lookalike segment and section names (`__TEXT\0junk`, Cyrillic `__tеxt`) | name-based rules (`findSegment`, YARA) |
| E19 | rwx segment, an executable segment of another name | W^X reviews |
| E20 | Code limit short: a valid signature over part of the code | "valid signature" as a trust signal |
| E21 | Entitlements edited after signing | entitlement review without hash check |
| E22 | Weakening entitlements, ad hoc, linker signed | notarization-shaped trust |
| E23 | Code modified after signing | hash mode marks the cdhash invalid; `verify` names the page |
| E24 | Encrypted segments (`cryptid`), Apple-protected segments | static analysis |
| E25 | Strip `LC_UUID`, randomize it, randomize `reserved`, `LC_SOURCE_VERSION`, `cpusubtype` capability bits | hash lists, UUID pivots |
| E26 | `LC_SEGMENT` (32-bit) in a 64-bit image: tools that parse both see a segment the kernel refuses | parsers that take both |
| E27 | A self-signed certificate shaped like Developer ID: `codesign -v` passes, the kernel runs it, only Gatekeeper refuses, and only when quarantined | "valid signature" and "Developer ID Application:" as trust signals |
| E28 | A development certificate from a real account: Apple-anchored, AMFI accepts it, Gatekeeper refuses it | reviews that check `anchor apple generic` alone |
| E29 | A Developer ID signature with an old secure timestamp: Gatekeeper's `legacy` path needs no ticket, and a revoked certificate is the only recourse | notarization as a gate |
| E30 | Restricted entitlements under an ad-hoc signature (`com.apple.private.*`, `aps-environment`): AMFI kills it, which a review of the plist alone does not say | entitlement review |

Out of this tool's reach, listed so nobody looks for them here: code in extended attributes (RustyAttr, 2024) and
resource forks; bundles (Info.plist, resources, `_CodeSignature/CodeResources`, `embedded.provisionprofile`);
revocation (syspolicyd checks it online, `kSecCSEnforceRevocationChecks`), notarization tickets (online or stapled
to the bundle, never in a Mach-O) and the quarantine attribute that decides whether Gatekeeper looks at all; dylib
hijacking by search path (`@rpath`, weak dylibs, writable directories); strings and symbols resolved at runtime
(`dlsym`, custom base64, Go/Rust obfuscation); PyInstaller archives inside an arm64 slice (Jamf, 2025); packers
other than UPX (none in the wild for Mach-O that this work could find).

## 6. How `verify` is built

Every rule of section 4 lives in one type, `MachOVerifier` (`Sources/fashion/MachO/Verifier.swift`, beside
`MachO.swift`, `Universal.swift`, `Editor.swift` and `Signer.swift`, the Mach-O layer): a verifier over one image, as
`MachOEditor` is an editor over one. It parses the segments and their sections once, then runs the groups dyld's own
validators suggest: the table, the segments, their sections, the entry point, what the image links, the extent,
`__LINKEDIT`, the padding, the signature. The universal file's rules, and a slice's against its table entry, are its
too. The `verify` subcommand (`Commands/Verify.swift`) only walks the files and prints the lines; what Security refuses
of a superblob comes back beside the lines and prints red after them, counted, as hash mode reports it. `hash
--verify` and `thinr --verify` run the same verifier on each file they work on and leave its findings in the unified
log alone, under the `verify` category, so a scan for another purpose records what is odd without printing it.

Headers only, but for three reads: the bytes no section or table covers (the padding alone), the signature's pages
(the signed extent once, as hash mode reads it), and the superblob's blobs against their special slots. The signer
is a fourth: `Signer` verifies the CMS blob as `SecStaticCode::verifySignature` does, through Security's `CMSDecoder`
and trustd, with no network, no anchors of its own and self-signed certificates as implicit ones, then classes the
chain as syspolicyd's `PolicyScanner` and libmis's `AMFIPathValidator` do: `anchor apple` (the Software Signing
marker under the Apple Code Signing CA), the App Store leaves, Developer ID under its CA, the development and
submission leaves, anything else Apple issued, and chains that end outside Apple's three roots.

The model carries what the rules need: `Universal` reads a 32-bit fat table one entry past its count, as Security's
`Universal` does, and counts that entry when it names arm64 (`Architecture.hidden`), a count of none included, so hash
mode, `thin` and `--exact` see the hidden slice too, and drops one that does not lie in the file, which verify alone
refuses; `MachO` keeps `ncmds`, `flags` and the 64-bit header's `reserved`, and
`fileRanges(of:)` names each range a command references; `EmbeddedCodeDirectory` reads its team identifier.

Adding a rule is a guard and a sentence in the group it belongs to, and a test that crafts the condition. Its doc
comment names the loader function it comes from, or the two readers it tells apart. Before it stays, it runs over the
OS trees and `/Applications` (section 7): a line true of the toolchain rather than of the file is noise, and the
rules below were dropped or narrowed for that.

**Dropped.** Non-zero bytes after the superblob inside `LC_CODE_SIGNATURE`'s range (272 of the OS's own arm64e slices
keep a stale signature's hashes there). Two `LC_BUILD_VERSION`, or a version-min command beside one, outside an
executable (zippered dylibs carry two, and the kernel's one-version rule is for the executable it loads). Non-zero
bytes in a gap shorter than the alignment of the section that follows (an older ld64 fills code alignment with no-ops
on x86_64: 862 Python extension modules). A signature size not a multiple of 16 (ld64's linker signatures). A section
align field past 2^15 (Tor Browser, numpy). `__DATA_CONST` without `SG_READ_ONLY` (177 Apple slices). An entitlement
line under the App Store leaf (60 slices of Keynote, Final Cut Pro, Apple Configurator and TestFlight carry
`com.apple.private.*` entitlements Apple provisions itself).

**Says nothing, on purpose.** A GPU image (`MH_GPU_EXECUTE`, `MH_GPU_DYLIB`, the slices of a Metal library), a dSYM,
an object file, a core and a dylib stub (`MH_DYLIB_STUB`, the simulator SDKs' `libLLVMContainer.dylib` lays its
sections at address 0), since no loader maps them; a universal file's slice of a CPU no loader knows is not called
"neither Mach-O nor an archive". An ad-hoc or linker-signed signature, the hardened runtime's absence. An Info.plist
slot left at zero.

**Named although the toolchain makes it.** An arm64 image without a signature: the kernel runs none, and a fresh
unsigned build is the one thing the toolchain makes that says so. A flat namespace: postfix's binaries are built so,
and it is the technique.

## 7. Calibration

The populations of section 2, in October 2026, each run after the rules settled.

**The OS.** 4,216 slices, 44 seconds with every CPU: 363 lines, all true of the files and none crafted: the postfix
binaries' flat namespace (246 slices), the entitlements that opt out of hardening where Apple grants them
(`disable-library-validation` on 71 slices, `allow-unsigned-executable-memory` on 14, `allow-jit` on 6,
`get-task-allow` on 5, `cs.debugger` on 2), Apple's own `LC_DYLD_ENVIRONMENT` (the BlastDoor services'
`DYLD_DLSYM_RESULT`, Safari's staged framework paths in `accountsd` and RemoteManagement, 36 slices), Rosetta's
runtime, a static executable, and OpenScripting's `AppletStub`, shipped with a signature removed. The signer rules add
nothing: every slice is Apple's. The header pad, section gaps, segment tails and inter-segment gaps are zero in every
slice. One bug the sweep found: a code directory with no special slots trapped `specialSlot`.

**Third-party software.** 27,967 slices of `/Applications`, Homebrew and `/usr/local`. The padding rules found four
real things: a PACE-protected dylib with 82 bytes in its header pad, Hopper's `__TP_CONST` tail, SkyTonight's
`__TEXT` tail, an updater's `__LINKEDIT`; and the no-op padding case the rule now skips. The signer rules add 24
lines: one app signed with an Apple Development certificate (VirusTotal.app and its Sparkle, 4 slices) and one
fuzz-corpus sample under iPhone Distribution; one app signed outside Apple's chains ("Hosting AU", by "Juno @Ju-X",
x86_64 and i386); five Ableton Live libraries whose Developer ID signatures are timestamped 2019-03-26, which
Gatekeeper's `legacy` rule runs without a ticket; and ten ad-hoc slices of jtool2 and Geekbench entitled to
`platform-application` and `com.apple.private.*`.

**The fuzzer.** Two harnesses of its own (`Fuzz/README.md`): `verify` runs the command's walk over the input as a
file, every rule, the universal file's and the signer's; `signer` takes a superblob alone, so that the fuzzer's
rewrites land in the CMS blob and its certificates, which the CMS signature does not cover, and trustd and
`SecCertificateCopyValues` read them as they come. Their seeds are the Mach-O fixtures of every test, the files the
verifier tests craft, and the superblobs cut out of them. An earlier run of the rules inside the Mach-O harness found
one trap in an older line, `Int32(self.filetype)` on a filetype past `Int32`, fixed and covered by a test; 2.9
million runs over both `--exact` endings found nothing after it.

### 7.1 The malware corpus

3,080,217 files: 145,207 files with a line, 242,536 lines, 606 red refusals. By kind, the largest first: signatures
whose code no longer hashes to a page (138,000 lines, nearly all OSX.DUBROBBER's copies, see below),
`get-task-allow` (28,775, iOS development builds), bytes appended (24,456), undated images (11,521), no `MH_PIE`
(10,923), non-zero fat padding (10,815, DUBROBBER's watermark and 42 old ppc fats, one with a timestamp string),
bytes past the last slice (4,534), no `LC_UUID` (2,239), bytes no section covers in `__TEXT` (1,399), a flat
namespace (761), a signature's residue (714), bytes no table references in `__LINKEDIT` (666), unsigned arm64 images
(550), UPX (425 as is, 121 signed after packing, 69 by a modified UPX), `__TEXT` rwx and `__XHDR` overlapping it
(358, 284: UPX 3.91), names with newlines in them, quoted on one line (481 sections of a BirdBox payload),
executables that link no dylib or name no dylinker (583, 514: UPX stubs), `ldid`-style signatures with a code
directory and no CMS blob nor an ad-hoc flag (137, iOS.AppBuyer and others), code directories covering past the image
or the signature (126, DevilRobber and HONKBOX samples cut short), and fat slices that are neither Mach-O nor an
archive under a known CPU type (129, Advanced Mac Cleaner's `infs` resources).

The corpus fixed four readings before its tally meant anything, each found by looking at the files behind a count
that was too round: a ppc image's `lc_str` offsets must be byte-swapped (14,827 names "not terminated" and 2,734
"linked no dylib" before that); an object file's one segment has no name and holds every section (`MH_OBJECT` says
nothing now); the i386 linker's `__IMPORT` segment is rwx by design (2,661 lines); a name with a newline in it broke
its line in two (names are shown quoted when not printable ASCII). A fifth came later: the kernel maps an arm64 image
on 4 KiB pages where its platform calls for them, iOS before 16 and tvOS, so the segment alignment rule takes the
platform's page rather than the linker's (201 lines on iOS 7-era samples).

What the run found, checked by hand:

- OSX.DUBROBBER: thousands of copies of a few signed agents (`yandexd`, `speedd`, `canaryd`, `Pods`), each with
  bytes appended, each failing its signature on the same page (`codesign` agrees: "code or signature have been
  modified"), and in one family ten bytes of `\` scattered through the zero padding before the first slice of the
  universal file, at offsets that differ per copy: a watermark in the fat padding, which Security's strict
  validation would refuse and nothing else looks at.
- An AV-Comparatives sample, a ppc and i386 universal file, with the string `1488904094.25`, a timestamp, in the
  padding between the fat table and its first slice; a Crisis sample dumped from memory, `_unpacked_2ndstub`, whose
  `__OBJC` data runs past its section table and whose segment has no name.
- 550 arm64 images without a signature, which the kernel does not run; 28,775 slices entitled to `get-task-allow`,
  iOS development builds.
- 1,399 slices with bytes no section covers in `__TEXT`, 666 with bytes no table references in `__LINKEDIT`, 284
  UPX 3.91 images whose `__XHDR` is rwx and holds unreferenced bytes.
- OSX.IronCore's unpacked images (589 slices) failing their first pages, OSX.HONKBOX's (24) failing page 0.
- 10,923 executables without `MH_PIE`, 761 with a flat namespace, 2,239 without `LC_UUID`: the age of the collection.

### 7.2 The live loaders

The sources above are the published ones; the loaders that run are newer. Read in IDA from the 26B118 shared cache
and kernelcache: dyld's strings hold a `Header` validator with rules the `common/` sources lack (section 4, "live
dyld"), and "code signature does not cover entire file up to signature", dyld's own name for the code-limit rule;
Security's `assure_signature_space` wants a signature size in multiples of 16; the kernel's strings are the sources'
(`multiple hash=%d CodeDirectories in signature; rejecting`, `disallowing unsupported code signature page shift`,
`multiple entitlements blobs`, `embedded signature doesn't match attached signature`) plus the W^X rule of
`vm_map_enter`, "curprot cannot be write+execute", which refuses a writable and executable segment on arm64. Those
that held against the OS and third-party sweeps became rules, with tests; three did not (section 6).

### 7.3 Gatekeeper and AMFI

syspolicyd (26B118) decides in `-[PolicyScanner policyMatchForCode:…]`, in this order, each a
`SecStaticCodeCheckValidity` with flags `0x10047` (all architectures, no executable or resource validation, network
allowed) against a requirement built in `-[PolicyScanner init]`: `anchor apple`; the Mac App Store
(`certificate leaf[field.1.2.840.113635.100.6.1.9]`, `.9.1` on internal builds); notarized, a ticket looked up by
cdhash, with the opaque-signature path for unsigned code (`checkOpaqueSignatureForCode:` signs it ad hoc in memory,
`ADHOC`, SHA-256, and looks that cdhash up, "Checking legacy notarization"); TestFlight (`6.1.25.1` under WWDR); and
Developer ID (`certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`),
notarized or `legacy`. Nothing else matches: not a development certificate, not a self-signed chain `codesign -v`
passes. Whether it evaluates at all is `determineGKEvaluationTypeForArguments:`: the quarantine attribute, a user
override, a script, a bundle, a notarized disk image as backing store, a library load.

AMFI's preflight (`+[AMFI preflightBinary:withPlatform:error:]` → `dlsym("AMFIExecutionPreflight")` in libmis)
builds an `AMFIPathValidator_macos` and `validateWithError:`: no signing identifier is `-421` (unsigned, allowed only
with SIP's `CSR_ALLOW_APPLE_INTERNAL` or `CSR_ALLOW_UNRESTRICTED_FS` off); `SecStaticCodeCheckValidity` failing is
`-420`; the entitlements are split by `matchIn` over two lists, `unrestrictedEntitlements` (exact
`com.apple.private.signing-identifier`, `com.apple.developer.hardened-process`; prefixes `com.apple.security.`,
`com.apple.developer.hardened-process.`) and `softRestrictedEntitlements` (`com.apple.application-identifier`,
prefix `com.apple.security.application-groups`); any other entitlement is validated against the
`restrictedRequirement` (`anchor apple`), then the QA App Store requirement on internal builds, then the bundle's
provisioning profile (`validateUsingMacOSProvisioningProfileWithRestrictedEntitlements:…`), and refused otherwise,
`-424` when the signature carries no certificate at all. `AMFIRequirementsManager` holds the requirements:
`developerRequirement` is the four development and submission leaves (`6.1.12`, `6.1.2`, `6.1.7`, `6.1.4`) under
`anchor apple generic`; `basicRequirement` adds `anchor apple`, the App Store leaf, Developer ID under its CA, and
the QA App Store leaf; `legacyDebuggerRequirement` is `anchor trusted and info[SecTaskAccess] = allowed`.

Security's side, from its sources: `verifySignature` decodes the CMS blob with the code directory as detached
content, verifies the signature, and builds the chain with no anchors and `CSSM_TP_ACTION_IMPLICIT_ANCHORS`, expiry
tolerated when no secure timestamp dates the signature; the team identifier is checked against the leaf's OU only
behind the certificates Apple issues to developers (`isAppleDeveloperCert`); `anchor apple` is the Software Signing
marker (`1.2.840.113635.100.6.22`) on a leaf under the "Apple Code Signing Certification Authority" intermediate, or
a cdhash in the trust cache; `anchor apple generic` is one of three roots, Apple Root CA, G2 and G3.

Tried on an arm64 Mac: a program signed with a self-signed certificate carrying Developer ID's markers runs (exit
42), `codesign -vv` says "valid on disk" and "satisfies its Designated Requirement", `spctl -a -t exec` says
"rejected"; `verify` says "signed outside Apple's chains by Developer ID Application: Fashion Test (FASHIONTM), which
Gatekeeper refuses". An ad-hoc signed arm64 program entitled to `com.apple.private.fashion` is killed at exec (exit
137); one entitled only to the soft-restricted `com.apple.application-identifier` and
`com.apple.security.application-groups` runs: the two lists hold.

## 8. Beyond naming: a canonical digest

Layer 5 follows from layer 3. Everything an adversary can change without changing what loads is the space a digest
should ignore: `--exact` already cuts appended bytes, `--unsign` the signature, `--unpack` the packer. The rest,
unreferenced bytes, `LC_UUID`, `reserved`, `LC_SOURCE_VERSION`, the order of load commands, fat padding, is small and
mechanical: a `--canonical` edit that zeroes those would give one digest to every copy that loads the same. Not
started; it adds a flag, so it is a proposal, not a change.

## 9. Sources

- xnu-12377.121.6: `bsd/kern/mach_loader.c` (`parse_machfile`, `load_segment`, `load_main`, `load_unixthread`,
  `load_dylinker`, `load_code_signature`, `pie_required`), `bsd/kern/mach_fat.c` (`fatfile_getarch`,
  `fatfile_validate_fatarches`), `bsd/kern/kern_exec.c` (`exec_mach_imgact` cputype check), `bsd/kern/ubc_subr.c`
  (`cs_validate_codedirectory`, `cs_validate_csblob`, entitlement slot checks).
- dyld-1378: `common/MachOFile.cpp` (`isMachO`, `forEachLoadCommand`, `validSegments`, `FatFile::isValidSlice`,
  `forEachSlice`, `entryAddrRegisterIndexForThreadCmd`, `enforceFormat`), `common/MachOAnalyzer.cpp`
  (`validLoadCommands`, `validLinkedit`, `validEmbeddedPaths`, `validMain`), `common/MachOLoaded.cpp`
  (`getLinkEditLoadCommands`), `mach_o/Image.cpp` (`isValidLinkeditLayout`).
- Security-61901.120.67: `OSX/libsecurity_utilities/lib/macho++.cpp` (`Universal::Universal`,
  `MachO::validateStructure`, `findArch`), `OSX/libsecurity_codesigning/lib/StaticCode.cpp` (`validateExecutable`,
  `validateDirectory`, `verifySignature`, `isAppleDeveloperCert`), `codedirectory.cpp` (`checkIntegrity`),
  `machorep.cpp` (`signingLimit`), `reqinterp.cpp` (`appleSigned`, `appleAnchored`, `certFieldGeneric`),
  `legacydevid.cpp` (`meetsDeveloperIDLegacyAllowedPolicy`), `csutilities.cpp` (`isAppleCA`,
  `certificateHasField`).
- syspolicyd and libmis (`AppleMobileFileIntegrity.framework`) of 26B118, decompiled: `-[PolicyScanner init]`,
  `policyMatchForCode:`, `checkOpaqueSignatureForCode:`, `determineGKEvaluationTypeForArguments:`,
  `AMFIExecutionPreflight`, `-[AMFIPathValidator_macos validateWithError:]`, `-[AMFIRequirementsManager init]`,
  `matchIn` and its two lists.
- The 26B118 dyld shared cache and kernelcache, for the strings of section 7.2; Rosetta's
  `/usr/libexec/rosetta/runtime` strings.
- Hidden arm64 slice: the `-hideARM64` era `lipo`, LLVM bug 42343, dyld's "Look for one more slice", Security's
  "Hack alert" 15001604.
- In the wild: OSX/Keydnap (ESET, 2016; modified UPX), RustyAttr (Group-IB, 2024; xattrs), PyInstaller stealers
  (Jamf, 2025), MetaStealer (SentinelOne; obfuscated Go), "Characterizing tactics, techniques, and procedures in the
  macOS threat landscape" (Computers & Security, 2026; 57,636 samples).
