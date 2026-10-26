# Fuzzing fashion's parsers

Every parser in fashion takes attacker-controlled bytes: a scan walks whatever tree it is pointed at. The harnesses
here feed libFuzzer's inputs through those parsers under AddressSanitizer, one entry point per surface, each an
`LLVMFuzzerTestOneInput` in its own file:

| Harness    | What it fuzzes                                                                                          |
| ---------- | ------------------------------------------------------------------------------------------------------- |
| `macho`    | `Universal.open`, the fat table, `MachO`'s load commands and every accessor the scan reads, both logical ends |
| `cdhash`   | `CDHash.hash`: the superblob, the code directories, the slot validator, ad-hoc synthesis, whole and `--exact` |
| `xar`      | `XARParser.hashToc`: the header, the table of contents as stored and inflated, under SHA-1, ssdeep and TLSH |
| `symhash`  | `SymHash.compute`: the symbol and string tables, the names windowed out of them, sorted and in table order |
| `diff`     | the digests `--match` is given: their shape, which names their algorithm, their typing into `Targets`, `TLSHBridge.diff` and `SSDeepBridge.compare` |
| `bytehash` | ssdeep's, TLSH's and git's hashers over the bytes, streamed from a file and whole in memory              |
| `unpack`   | `MachOEditor.edit`: UPX's pack header, with its marker and without, UCL's decoders and liblzma, the unfilters, signature removal, the universal rebuild; then the edit read as the scan reads it, walked, cdhashed and symhashed across its pieces |

An input reaches a parser as a `File`, the way a test fixture does: written over one scratch file per process and
opened from there (`support.swift`). `macho`, `cdhash` and `unpack` are built with both `--exact` endings (see
Package.swift): `fuzz-macho`, `fuzz-cdhash` and `fuzz-unpack` with `SECURITY_STRICT_VALIDATION`, the `-segments` ones
without.

## Running

```sh
make fuzz-run                 # build, seed, then fuzz every harness for 15 minutes, 2 workers each
make fuzz-run FUZZ_SECONDS=60 # shorter
make fuzz-run FUZZ_HARNESSES="unpack diff" FUZZ_JOBS=8   # some harnesses, more workers each
make fuzz                     # build only
make fuzz-seed                # seed only
```

`fuzz.sh` does the work and documents its steps. `FUZZ_JOBS` sets the workers per binary, every binary run getting that
many, so their product should stay near the cores: libFuzzer's 10-second limit counts wall time, and on an
oversubscribed machine a slow unit passes for a hung one; the script warns past it. Everything lands under
`.build/fuzz/`, which git ignores: the binaries in `bin/`, the corpora in `corpus/<harness>/`, each run's logs in
`logs/<binary>/` and what it found in `artifacts/<binary>/`. `Fuzz/fuzz.sh summary` reads the last run's logs back.

The corpora are seeded with every fixture the tests build (hand-made, compiled or codesigned: `FASHION_FIXTURES` in
TestHelpers.swift keeps them while `swift test` runs), with `/bin/ls` whole and by slice, with a XAR of this directory,
and with TLSH and ssdeep digests of real files. The packed images among them come from the `upx` installed; one packed
with filter 0x53 for arm64 needs a UPX newer than 5.2.1, which packs with 0x52. The `.dict` files give libFuzzer the
magics, load commands, segment names and code-signature versions it would otherwise have to guess, and `unpack.dict`
UPX's: its marker, versions, formats, methods, filters and LZMA's properties.

To reproduce a finding, run its binary on the artifact; to shrink it first, let libFuzzer minimize it:

```sh
.build/fuzz/bin/fuzz-cdhash .build/fuzz/artifacts/fuzz-cdhash/crash-<sha1>
.build/fuzz/bin/fuzz-cdhash -minimize_crash=1 -runs=100000 .build/fuzz/artifacts/fuzz-cdhash/crash-<sha1>
```

A crash, an input that takes more than 10 seconds (`timeout-`), one that pushes the process past 2 GiB
(`oom-`) or a single allocation past 512 MiB counts as a finding; the unpack binaries may allocate 1 GiB, see below.

## Building

The harness is built outside SwiftPM: an executable target cannot depend on the `fashion` executable target, so
`fuzz.sh build` compiles `Sources/fashion` the way SwiftPM compiles it for the tests (testable, its entry point renamed
to `fashion_main`), ArgumentParser from the checkout SwiftPM resolves, the C targets with the module maps SwiftPM would
write, and links each harness against them. LZMA is decoded by the liblzma macOS ships, declared by `Bridges/CLZMA`'s
own module map: linked, neither instrumented nor sanitized, so the fuzzer drives it but sees no coverage inside it.

Xcode's toolchain ships AddressSanitizer's runtime but not libFuzzer's, and `swiftc` refuses `-sanitize=fuzzer` for
want of it, so the flag goes straight to the frontend (`-Xfrontend -sanitize=fuzzer,address`) and the archive,
`libclang_rt.fuzzer_osx.a`, is taken from the toolchain when a future one ships it, else from Homebrew's LLVM, which
the Brewfile at the root of the project lists:

```sh
make brew
```

Only the archive is used from there; the compiler stays Xcode's.

## What it can find, and what it cannot

A memory error, a Swift trap (an overflow, an index past a buffer, a failed conversion), an input that takes seconds,
or one whose allocations outgrow the input by orders of magnitude. Inputs stay under `max_len` (256 KiB for a Mach-O,
64 KiB for a XAR), so a limit that only a file of gigabytes reaches, like a page size that would have the validator
buffer a whole slice, is beyond it unless the cost shows at this scale too; those limits remain the reviews' to check.
One such limit is allowed for: a pack info may claim an image of up to the 768 MiB UPX allows, which `unpack()`
allocates before it decodes a block and `fashion --unpack` then rejects in milliseconds, the buffer never touched, so
the unpack binaries' allocation limit is 1 GiB rather than 512 MiB, and a claim under the ceiling is no finding.

