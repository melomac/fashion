# fashion

`fashion` hashes a file tree the way a malware analyst needs it hashed: a macOS binary as it was before someone padded it, signed it again, packed it with [UPX][], or hid the packer's marker, so copies of one sample get one digest and match a threat intelligence list that mixes algorithms.

It is a native Swift command-line tool, hosted on [Codeberg](https://codeberg.org/melomac/fashion "Codeberg: melomac/fashion") and mirrored on [GitHub](https://github.com/melomac/fashion "GitHub: melomac/fashion"), with no runtime dependency: ssdeep, TLSH, and UPX's UCL decoder are bridged as submodules, LZMA comes from the liblzma macOS ships.

Hashing reads files and writes nothing.
A restored binary is written only when the `thin`, `unsign`, or `unpack` subcommand asks for it, beside the file, and never carries the execute bit; `fashion` never runs anything.
What it undoes, Apple's and UPX's own tools undo too, `codesign --remove-signature` and `upx -d`; `fashion` adds the fidelity a digest needs, and sees what those tools give up on.

* [SHA-2][] (SHA-256 by default), insecure [SHA-1][] and [MD5][], from [CryptoKit](https://developer.apple.com/documentation/cryptokit/ "Perform cryptographic operations securely and efficiently.")
* fuzzy [ssdeep][] and [TLSH][], with a similarity or distance score when matching
* [CDHash][] of Mach-O binaries, the identity \*OS uses: embedded when signed, synthesized as `syspolicyd` does when not
* [symhash][] of Mach-O binaries, with any algorithm, separator, and optional sort
* [XAR][] archives (macOS packages) table of contents checksum, with any algorithm and optional decompress (zlib)
* [git-hash-object][]
* matching many digests of mixed algorithms in one pass, every file read once
* a Mach-O as it was before bytes were appended, before signing, before UPX packing, whole or by architecture
* multithreading

Multithreaded with `--jobs 0` or the `-J` shortcut, `fashion` is very fast and stays well under 150 MB of memory:

| Machine             | Jobs | App count |   File count    | SHA-256 duration | TLSH duration |
|:--------------------|:----:|:---------:|:---------------:|:----------------:|:-------------:|
| Mac Studio M2 Ultra |  24  | 274 apps  | 1,268,657 files |   1 min 6 secs   | 1 min 25 secs |
| MacBook Air M4      |  10  | 213 apps  |   813,217 files |        54 secs   | 1 min 42 secs |

## Install

A signed and notarized binary is available via Homebrew 🍻

```bash
brew tap melomac/tap https://codeberg.org/melomac/homebrew-tap
brew trust melomac/tap
brew install melomac/tap/fashion
```

## Quick tour

Hash a tree, SHA-256 by default, every CPU at work:

```bash
fashion -J /usr/bin
```

Find the files on a list of digests, whatever their algorithms:

```console
$ fashion --match $(fashion -q --algo md5 /usr/bin/true) --match $(fashion -q /usr/bin/false) --match $(fashion -q --algo tlsh /usr/bin/yes) /usr/bin/
0b778f18b68fe47b9b8704b3a0e968e7  /usr/bin/true
T180F51D6B69625063D894CE7867799A524B14F2A3C18E0472F173B739FDCEB97C2030DA    0  /usr/bin/yes
ccdd13063a974daa3ffcb707ac70104fb642eaf4aab3b621e816f36e2e8b59ab  /usr/bin/false
```

See two copies of one sample as one, whatever was done to them since:

```console
$ fashion prostorify.com/*/bin/Pods --exact
eaf8c357224751a209c0d164c779da7c77c6369f04a94f5ea6efbe21fda62930  prostorify.com/agent/bin/Pods
eaf8c357224751a209c0d164c779da7c77c6369f04a94f5ea6efbe21fda62930  prostorify.com/sys/bin/Pods

$ fashion ls ls_resigned --unsign
5bffa3946ea6e8edd6cf46f82a099fc187849ad1001ef0a7172757fac2b7f2c2  ls
5bffa3946ea6e8edd6cf46f82a099fc187849ad1001ef0a7172757fac2b7f2c2  ls_resigned

$ fashion ls_x86_64_unsigned ls_x86_64_unsigned_upx --unpack
42945e750e5f575470800ae39cbbd41cabad97a64d7702c04a7e81fde710fb20  ls_x86_64_unsigned
42945e750e5f575470800ae39cbbd41cabad97a64d7702c04a7e81fde710fb20  ls_x86_64_unsigned_upx
```

Write those restored binaries out, for a diff or a disassembler:

```console
$ fashion thin --unsign --unpack sample
sample_x86_64
sample_x86_64_unsigned
sample_x86_64_unsigned_unpacked
sample_arm64
sample_arm64_unsigned
```

## Comparing binaries

A digest tells two files apart by any byte.
An adversary uses that: the same payload is shipped padded with junk, signed with another identity, or packed, and each copy gets a digest of its own.
Each flag below undoes one of those changes before hashing, so the copies collapse to one digest, with any algorithm, and a `--match` target computed on one copy finds the others.

| The copies differ by                  | Flag            | What `fashion` hashes                                                  | As                                           |
|:--------------------------------------|:----------------|:-----------------------------------------------------------------------|:---------------------------------------------|
| bytes appended after the Mach-O       | `--exact`       | the Mach-O image, up to where `codesign` expects the file to end       | `codesign` reads it                          |
| a code signature                      | `--unsign`      | the code without its signature, laid out as the linker left it         | `codesign --remove-signature`, then restored |
| UPX packing, its marker hidden or not | `--unpack`      | the code as it was before packing, past a signature added since        | `upx -d`, where it gives up too              |
| the architectures bundled with it     | `--slices`      | each architecture on its own, besides the whole file                   | `lipo -thin`                                 |
| everything but the imports            | `--symhash`     | the list of external symbols                                           | ImpHash, VirusTotal                          |
| what the kernel checks                | `--algo cdhash` | the CodeDirectory, embedded or synthesized ad hoc as `syspolicyd` does | the kernel and `syspolicyd`                  |

The flags combine: `--slices --exact --unsign --unpack` hashes each architecture of a universal file, trimmed, unsigned, and unpacked.
Files that are not Mach-O are hashed whole.
All of it happens in memory: the hash flags write nothing to disk.

### Appended bytes

Some malware families append garbage data after the Mach-O structure to evade hash-based detection.
With the `--exact` flag, we hash only the Mach-O image — up to the end of its `__LINKEDIT` segment or symbol table strings, whichever its load commands declare first, where `codesign` expects the file to end — so the same payload padded with different trailing junk collapses to one digest:

```console
$ fashion prostorify.com/*/bin/Pods
73438af4c465a58aa019bce5c165bfb16be51549bcfb468ab1643bf205ea0ab6  prostorify.com/agent/bin/Pods
7a95a2e3f94e635cc02c38931bc7eeb65f9f70405d2b104139815d28b57d3992  prostorify.com/sys/bin/Pods

$ fashion prostorify.com/*/bin/Pods --exact
eaf8c357224751a209c0d164c779da7c77c6369f04a94f5ea6efbe21fda62930  prostorify.com/agent/bin/Pods
eaf8c357224751a209c0d164c779da7c77c6369f04a94f5ea6efbe21fda62930  prostorify.com/sys/bin/Pods
```

`--exact` works with any algorithm and combines with `--slices` to trim each architecture of a universal binary.

With `SECURITY_STRICT_VALIDATION=NO` in the build environment, `--exact` keeps every byte the segments and link-edit tables reference instead, so a dSYM keeps the `__DWARF` segment that follows `__LINKEDIT`, and a slice with a load command `fashion` does not model is hashed whole.

### Signatures

A sample signed again gets a new digest, though its code is identical.
With the `--unsign` flag, we hash a Mach-O without its code signature, as `codesign --remove-signature` leaves it, then restored as the linker left it: the `__LINKEDIT` vmsize rounded to the linker's page, where `codesign` leaves the 16 KiB the signature needed, and a universal file laid out as `lipo` lays it out, where `codesign` moves every architecture to 16 KiB.

Copies signed by different identities then hash the same, and a binary signed after it was linked hashes as it did before:

```console
$ fashion ls ls_resigned
a7a0dcb67e60a7b726801c220a17ed7e139c99fe7c7bbacf4880e9779ba11e9c  ls
b0826588e029f26a035105612e1a36d31b22bf27aa4af8ad65950079286d4685  ls_resigned

$ fashion ls ls_resigned --unsign
5bffa3946ea6e8edd6cf46f82a099fc187849ad1001ef0a7172757fac2b7f2c2  ls
5bffa3946ea6e8edd6cf46f82a099fc187849ad1001ef0a7172757fac2b7f2c2  ls_resigned
```

`--unsign` works with any algorithm and combines with `--slices` and `--exact`; with `--algo cdhash`, each architecture gets the `ADHOC` cdhash of its unsigned code.
A signature changes neither the symbols nor a XAR table of contents, so `--symhash` and `--xar-toc` refuse it.
Unsigned files are hashed as they are.
Like `codesign`, we refuse to remove a signature that appended bytes follow; `--exact` drops them first.

### UPX packing

Malware has long been packed with [UPX][] on macOS, and `upx -d` gives up on a packed sample signed afterward: the signature hides the 16-byte `__LINKEDIT` UPX left.
With the `--unpack` flag, we hash a Mach-O UPX packed as it was before packing, as `upx -d` unpacks it, natively with UPX's own UCL decoder and macOS's liblzma, looking past a signature added after packing:

```console
$ fashion ls_x86_64_unsigned ls_x86_64_unsigned_upx
42945e750e5f575470800ae39cbbd41cabad97a64d7702c04a7e81fde710fb20  ls_x86_64_unsigned
b1c78d8c14ed989407d34ddaa590886596b665bcf4ca19f016e1d8ba985348f2  ls_x86_64_unsigned_upx

$ fashion ls_x86_64_unsigned ls_x86_64_unsigned_upx --unpack
42945e750e5f575470800ae39cbbd41cabad97a64d7702c04a7e81fde710fb20  ls_x86_64_unsigned
42945e750e5f575470800ae39cbbd41cabad97a64d7702c04a7e81fde710fb20  ls_x86_64_unsigned_upx
```

A modified packer replaces the `UPX!` marker so that `upx -d` calls the file not packed and gives up.
`fashion` finds the packed layout by its structure and checksum, unpacks it anyway, and warns with the marker it found in place of `UPX!`.
A pack header overwritten to defeat `upx -d` leaves the file unpacked, and packed data that does not hold is reported in red.

We follow UPX 5's own unpacker, for what UPX 3.91 and later packed: x86_64, arm64, i386, arm, and ppc executables, and x86_64, i386, and ppc dylibs, with NRV or LZMA, thin or in a universal file, which is then laid out as `lipo` lays it out.
`upx -d` also gives up on an arm64 binary whose packed `__TEXT` is a single 16 KiB page, which we unpack too.
`--unpack` works with any algorithm and every mode but `--xar-toc`, `--symhash` then hashing the symbols of the unpacked code; outside `--symhash`, it combines with `--unsign`, which removes the unpacked code's own signature.

### Architectures

`fashion` parses universal and thin Mach-O binaries natively.
The `--slices` flag hashes each architecture individually in addition to the whole file.

Architecture names come from the OS's own Mach-O naming. It's notably the source `codesign` uses, so they read `arm64`, `arm64e`, `arm64e.x1`, `x86_64`, `x86_64h`, `i386`, legacy `ppc` / `ppc64`, and so on.
A slice the running OS cannot name yet falls back to a built-in table (`arm64e.x1` on macOS 26 and earlier), then to `unknown(cputype,cpusubtype)` like `lipo -archs`.

Like `codesign`, `fashion` reads a slice's load commands, code signature, and embedded Info.plist into memory at the sizes they declare, which a crafted file can make as large as the file itself.

### Symbols

Following the convention used by ImpHash, symhash, and tools like [VirusTotal](https://www.virustotal.com/), `--symhash` mode defaults to the MD5 of the ordered external symbol list joined by the `,` separator, but you can pick any algorithm or separator, and keep the symbol list as is.

```console
$ fashion --symhash --algo ssdeep --match $(fashion --symhash --algo ssdeep admobs.ru/agent/bin/Pods --quiet) admobs.ru
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/agent/bin/cat
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/agent/bin/Pods
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/sys/bin/Pods
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/d
```

### CDHash

The CodeDirectory Hash is how \*OS identifies an executable: the hash of the directory that holds a hash of every code page, so it changes with any byte of code.
`fashion` prints the CDHash of Mach-O binaries, one line per code directory, in the kernel's preferred order ([XNU][]).

A binary signed with multiple algorithms gets multiple lines, each labeled with its hash type: `sha1`, `sha256`, `sha256t`, `sha384`, `sha512`.
We print the untruncated `CandidateCDHashFull`, and `--match` accepts it as well as the `CDHash` Apple's tools usually show, truncated to 40 hex digits.

When `/usr/libexec/syspolicyd` meets unsigned code, it has the Security framework sign it in memory and looks up a notarization ticket for the computed hash.
`fashion` builds the same signature and prints its CDHash, labeled `ADHOC`:

* the `ADHOC, sha256` line is, byte for byte, the hash `syspolicyd` looks up;
* the `ADHOC, sha1` line is its legacy counterpart.

A signature Security rejects counts as none, as `codesign` says "not signed at all": the file gets its `ADHOC` lines too, computed up to where the signature starts.

Each signed slice's code is checked against its signature, as `codesign --verify` does, which reads every page of it.
A slice whose signature does not hold is labeled `INVALID`, and named on standard error without changing the exit status: "signature rejected, hashed as unsigned", or "invalid signature (code or signature have been modified)" when a byte of code changed since signing.

Mach-O files that are not code to `codesign` — object files, dSYMs, core dumps, kernel filesets — have no identity of either kind and yield no line, signed or not.

This is not documented, so we mirror the Security framework and `syspolicyd` code, decompiled with [IDA Pro](https://hex-rays.com/ida-pro/ "A powerful disassembler, decompiler and a versatile debugger. In one tool.") driven through [ida-mcp](https://hex-rays.com/blog/hex-rays-ida-mcp-server "Meet the official IDA MCP server: free, open source, and model-agnostic. Connect IDA to AI agents and cut token use by ~20% with Code Mode.").
`fashion` keeps their structure and names so the two can be read side by side.

Every rule is checked against `/usr/bin/codesign`: the tests compare `fashion`'s `ADHOC` lines with `codesign --detached -s - --identifier ADHOC` on real and crafted binaries, so a change in the Security framework shows up as a failing test rather than as a silent drift.

### Packages

Installation packages on macOS.
According to [xar(1)](x-man-page://1/xar "man 1 xar"):

>xar is no longer under active development by Apple. Clients of xar should pursue alternative archive formats.

The eXtended ARchive header is straightforward, so we implement our own parser to read the table of contents (TOC) instead of bridging the library.

Just like `xar --dump-toc-cksum`, `--xar-toc` mode defaults to the SHA-1 of the compressed TOC, but you can choose any algorithm and even have the TOC decompressed (zlib).

## Matching

Use `-m` / `--match` to search for files matching one or more digests.

```console
$ fashion --algo tlsh --match $(fashion --quiet --algo tlsh /usr/bin/true) /usr/bin/
T1B683F9DB67586C65EC98A97412CEE6237F33E7950FA2401760A1C4E93E437B67E3980C   40  /usr/bin/update_dyld_shared_cache
T10483D9DF1B582C51ED4C987012CEA6677F33E7950F92422B60A1C4E92E437BB6E3984C    0  /usr/bin/true
T16083DADB57582C64EC989C7412CEA727BF33E7550B92412B60A1C4EA3E437B67E3584C   26  /usr/bin/false
```

With the quiet flag, we only print matching paths.

Targets of several algorithms go in one run, as a threat intelligence list mixes them: without `--algo`, the shape of each target picks its hash function, and every file is read once and hashed with each function the targets need.
A match line shows the digest that matched, with its score when fuzzy.

A `git` or `git256` digest is shaped like a SHA-1 or SHA-256 one, so a target of 40 or 64 hex digits is a file's SHA-1 or SHA-256 unless `--algo git` or `--algo git256` says otherwise; a CDHash takes `--algo cdhash`, which accepts the truncated form Apple's tools show, 40 hex digits, as well as the full one.

| Shape                                  | Algorithm |
|:---------------------------------------|:----------|
| 32 hex digits                          | `md5`     |
| 40 hex digits                          | `sha1`    |
| 64 hex digits                          | `sha256`  |
| 96 hex digits                          | `sha384`  |
| 128 hex digits                         | `sha512`  |
| `T1` and 70 hex digits, or 70 alone    | `tlsh`    |
| `blocksize:chunk:chunk`, base64 chunks | `ssdeep`  |

```console
$ fashion --match $(fashion -q --algo md5 /usr/bin/true) --match $(fashion -q /usr/bin/false) --match $(fashion -q --algo tlsh /usr/bin/yes) /usr/bin/
0b778f18b68fe47b9b8704b3a0e968e7  /usr/bin/true
T180F51D6B69625063D894CE7867799A524B14F2A3C18E0472F173B739FDCEB97C2030DA    0  /usr/bin/yes
ccdd13063a974daa3ffcb707ac70104fb642eaf4aab3b621e816f36e2e8b59ab  /usr/bin/false
```

Hex digits are matched in either case.

The shape picks the function and the mode flags pick the input, as without `--match`: under `--symhash` a 40 hex target is the SHA-1 of the symbol list, under `--xar-toc` of the table of contents, under `--slices` of each architecture too, `--exact` trims the Mach-O first, `--unsign` removes its signature, and `--unpack` unpacks it.

With `--algo`, every target is compared with that algorithm, and one shaped otherwise is a usage error; without it, a target shaped like no digest is one. Either exits 64 before hashing anything.

A fuzzy match has a threshold, `-s` / `--score`: the minimum ssdeep similarity or the maximum TLSH distance, 40 by default.
`--xlen` needs a TLSH target among them, with or without `--algo`; see [TLSH](#tlsh) for what it leaves out.

## Writing restored binaries

Nothing is written unless you ask for it: the three subcommands below, and only they, write what the hash flags see, beside the file, for a diff, a disassembler, or another tool.
Every artifact is written without the execute bit, whatever the source file carried, so none can be run by accident; an unsigned arm64 one would not run on Apple silicon anyway.

### thin

`fashion thin` writes each architecture of a universal Mach-O beside it, like `lipo -thin` would, named as `codesign --arch` spells them: `ls` gives `ls_x86_64`, `ls_arm64e`, and `ls_arm64e.x1`.
With `--exact`, we compute the logical Mach-O image end, so appended bytes are dropped; with `--unsign` or `--unpack`, we write each architecture without its code signature or unpacked, as with the hash mode's flags.
A thin Mach-O these flags change gets an artifact too.

The flags leave the way behind them: every state a slice goes through is written, the slice as the fat table places it, then cut, then without its signature, then unpacked, then the unpacked code cut and without its own signature, as far as the flags take it.
A signature added after packing has to come out before the code is unpacked, so `--unpack` writes that state too.

```console
$ fashion thin --unsign --unpack sample
sample_x86_64
sample_x86_64_unsigned
sample_x86_64_unsigned_unpacked
sample_arm64
sample_arm64_unsigned
```

An artifact the flags change is named for what they did, in the order they did it: `_exact`, `_unsigned`, then `_unpacked`, and the unpacked code's own `_exact` and `_unsigned`, after the architecture of a universal binary's slice, `ls_x86_64_unsigned`, or after the name of a thin file, `sample_unsigned_unpacked`.
One they leave as it is keeps its name, and a thin file they leave as it is gets none.
So artifacts stand beside each other, and a later run with other flags over an earlier artifact makes what one run with them all would: `ls_x86_64` unsigned is `ls_x86_64_unsigned` either way, found already in place.

### unsign and unpack

`fashion unsign` writes a Mach-O beside it without its code signature, as the `--unsign` flag hashes it, and `fashion unpack` with what UPX packed unpacked, as the `--unpack` flag hashes it: `ls` gives `ls_unsigned`, and `ls_upx` gives `ls_upx_unpacked`.
Where `thin` writes each architecture of a universal binary as a file of its own, and every state on the way, these go straight to the artifact and write the file whole, its architectures laid out again as `lipo` lays them out: `fashion unsign ls` writes what `lipo -create` makes of the unsigned slices `fashion thin --unsign ls` writes, byte for byte.
`--exact` drops appended bytes first, so a signature they follow comes off, and `--overwrite` replaces a different file under an artifact's name, as with `thin`.
A file with nothing to unsign or unpack gets no artifact.

Artifacts are named and chain as `thin`'s do: `fashion unpack` over a packed `sample` signed afterward writes `sample_unsigned_unpacked`, what `fashion thin --unpack sample` writes last.

### What is left alone

An identical artifact already in place is left alone.
A different file under an artifact's name is reported and left alone, unless `--overwrite` replaces it with a new file renamed over the name, as `lipo` writes its output, so a file a hard link there leads to keeps its bytes; either way the unified log records both sizes and SHA-256.

A symbolic link is never followed or replaced: a safety rule for other files.

## Running it

### Subcommands

`fashion` runs its `hash` subcommand unless another is named, so `fashion [options] <paths>` and `fashion hash [options] <paths>` are the same command.
`fashion --help` shows the options of `hash`, and `fashion help` lists the subcommands; a path spelled like a subcommand is given after the `--` that ends the options.

### Quiet

With the `-q` / `--quiet` flag, we only print file digests, or matching paths in match mode.

### Concurrency

The `-j` / `--jobs` flag controls parallel workers.
Set `-j 0` or `-J` to use all CPU cores.

The `--sort` flag prints files in the natural order of paths: a run of digits sorts as a number, so `file-2` comes before `file-10`, and any other byte as itself, so the order holds in every locale.
The walk sorts each directory as it reads it, so hashing starts right away, and a file's lines wait until every file before it has printed.

Enumeration is demand-driven, so the walk never runs far ahead of hashing.

The `-L` / `--follow` flag follows symlinks while walking; by default they are skipped.
A symlink named directly on the command line is always followed, like `find -H`.
Only regular files are hashed: a FIFO, device, or socket is skipped, whether named on the command line or met in a directory.

### Colors

On a terminal, `fashion` colors lines by what they tell:

🟢 **Green**:

* a full match with any algorithm: a digest, a symhash, a cdhash, `ADHOC` included;
* a fuzzy match, darker greens as the distance grows toward the `--score` threshold;
* a TLSH distance from 300, where [false positives][TLSH paper] pass 79%, is gray whatever the threshold,  
  unless `--xlen` leaves out the length those rates count;

🔴 **Red**: a file `fashion` can't parse, a malformed Mach-O, signature, XAR, or UPX pack;

🟡 **Yellow**: anything else `fashion` reports on standard error: a file that can't be read, a signature that doesn't hold, a packer's marker replaced, or a file TLSH can't hash;

⚪️ **Dimmed**: synthesized `ADHOC` lines, for unsigned code.

A terminal with 16 colors, by `TERM` and `COLORTERM`, gets its own green, dimmed as soon as a match is not full.
Set `NO_COLOR=1` to turn this off.

### Exit status

`fashion` follows the grep/codesign convention so it can be scripted:

|  Code  | Description                                                     |
|:------:|:----------------------------------------------------------------|
| **0**  | ✅ success — in match mode: at least one file is matched        |
| **1**  | ❌ match mode: no file matched                                  |
| **2**  | ❌ one or more paths couldn't be enumerated, hashed, or written |
| **64** | ❌ usage: invalid options, or an argument that isn't UTF-8      |

Per-path failures (a missing path, a permission-denied directory, an unreadable file, one that changed or was replaced while it was hashed, a name that is not UTF-8, a malformed Mach-O in a mode that parses it) are written to standard error and set exit code `2`.
They never abort the rest of the scan.

### Completion

[swift-argument-parser](https://github.com/apple/swift-argument-parser "Straightforward, type-safe argument parsing for Swift") provides free completion for bash, fish, and zsh:

```bash
fashion --generate-completion-script
```

With [fish-shell](https://github.com/fish-shell/fish-shell/ "The user-friendly command line shell."), you can even source the generated completion script on demand, and it will remain for the session:

```bash
echo "fashion --generate-completion-script fish | source" > ~/.config/fish/completions/fashion.fish
```

Very convenient when you craft your own tools.

## Algorithms

Project algorithm choices are driven by interoperability with existing tools and formats.

[SHA-2]: https://en.wikipedia.org/wiki/SHA-2 "Wikipedia: SHA-2"
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1 "Wikipedia: SHA-1"
[MD5]: https://en.wikipedia.org/wiki/MD5 "Wikipedia: MD5"
[ssdeep]: https://github.com/ssdeep-project/ssdeep "GitHub: ssdeep-project/ssdeep"
[TLSH]: https://github.com/trendmicro/tlsh "GitHub: trendmicro/tlsh"
[TLSH paper]: https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf "TLSH - A Locality Sensitive Hash, Tables I and II"
[SymHash]: https://www.anomali.com/blog/symhash "SymHash: An ImpHash for Mach-O"
[CDHash]: https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes "TN3126: Inside Code Signing: Hashes"
[XAR]: https://github.com/apple-oss-distributions/xar/ "GitHub: apple-oss-distributions/xar"
[Git-Hash-object]: https://git-scm.com/docs/git-hash-object "Git: hash-object"
[XNU]: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c "XNU: hashPriorities in ubc_subr.c"
[UPX]: https://upx.github.io "UPX: the Ultimate Packer for eXecutables"

### Insecure MD5 and SHA-1

MD5 and SHA-1 both have known [collisions](https://en.wikipedia.org/wiki/Collision_attack#cite_note-md5-2004-1) and are considered insecure.

### ssdeep

Clang's `-Wshorten-64-to-32`, which Xcode and SwiftPM enable, flags three implicit conversions in ssdeep's `edit_dist.c` and `fuzzy.c`, so every build of `fashion` printed them.
All are lossless, bounded by the 64 characters of a spamsum, and [pull request #43](https://github.com/ssdeep-project/ssdeep/pull/43 "GitHub: ssdeep-project/ssdeep PR43: Silence -Wshorten-64-to-32 in edit_distn and score_strings") removes them without changing a digest or a score.
Until it merges, the ssdeep submodule tracks that branch of [a fork](https://github.com/melomac/ssdeep/tree/shorten-64-to-32 "GitHub: melomac/ssdeep, branch shorten-64-to-32") instead of ssdeep-project.

### TLSH

Trend Micro's library counts the total data length using an `unsigned int data_len`, i.e. 32-bit, so any file larger than ~4 GB is undefined behavior.
Even worse, in Java, the code was using a signed integer (~2 GB).

`fashion` follows Trend Micro's recommendations and backports the Java fix from TLSH 4.6.0 to define the TLSH of a file as the TLSH of its first ~4 GB.
The `tlsh` tool reads a file's size into a 32-bit `int` instead: it calls a file "too small" when that size modulo 4 GiB is 2 GiB or more, and hashes only that many bytes of any other.

`fashion` names on standard error each file TLSH cannot hash: under 50 bytes, with too little variation, and greater than ~4 GB ([discussion](https://github.com/trendmicro/tlsh/issues/84)).
Neither changes the exit status, and `--quiet` leaves them out.

A TLSH distance counts file length: padding, such as appended null bytes, adds to it even when the content is the same.
`--xlen` leaves the length out of `--match`, as the `tlsh` tool's `-xlen` does: a 50 KB binary padded with zeros to 2.9 MB is then 1 away from itself instead of 505.
`--exact` trims a Mach-O to its logical extent instead, but cannot trim a digest computed elsewhere; ssdeep is not affected by zeros.

### Git hash

The `git` and `git256` algorithms compute the hash of a [Git](https://git-scm.com/) blob object.
With the digest, you can look for the object across all branches and commits of a repository.

```console
$ git log --raw --all --format='%h %s' --find-object=$(fashion --algo git --quiet .swiftformat)
7f1a770 initial public release

:000000 100644 0000000 842281a A        .swiftformat
```

## History

The original `fashion` was a workaround for repetitive loading of the Perl command `shasum`.

The name is a mashup of my original bash function `fsha` and the David Bowie song, more specifically [the duet](https://www.youtube.com/watch?v=3I-4ck0NXwA&t=928s "David Bowie & Friends: A Very Special Birthday Celebration Concert NYC 1997") with Frank Black of the Pixies.

Python made it very easy thanks to the built-in hashlib, io, and the [python-ssdeep](https://github.com/DinoTools/python-ssdeep "GitHub: DinoTools/python-ssdeep") or tlsh / [py-tlsh](https://github.com/trendmicro/tlsh/tree/master/py_ext/pypi_package "GitHub: trendmicro/tlsh Python module") modules were straightforward.
But [uv](https://docs.astral.sh/uv/ "An extremely fast Python package and project manager, written in Rust.") was [complaining](https://github.com/DinoTools/python-ssdeep/pull/70/changes#diff-60f61ab7a8d1910d86d9fda2261620314edcae5894d5aaa236b821c7256badd7R8 "GitHub: DinoTools/python-ssdeep PR70") about pkg_resources, and I needed features Python couldn't give me without significant effort.

So here we are: Swift, native, concurrent, with C and C++ dependencies bridged as submodules, and zero external runtime requirements.

## License

`fashion` is licensed under the [GNU General Public License version 3](https://codeberg.org/melomac/fashion/src/LICENSE).
The binary includes third-party code from [ssdeep][] (GPL-2.0-or-later), [TLSH][] (used under BSD-3-Clause), and [UPX][] and its UCL library (GPL-2.0-or-later): [NOTICE](https://codeberg.org/melomac/fashion/src/NOTICE) carries their copyright notices and license terms.
