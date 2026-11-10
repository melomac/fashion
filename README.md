# fashion

`fashion` is a Swift command-line interface to traverse a file hierarchy and **compute or match popular hash digests**.

The project is hosted on [Codeberg][], mirrored on [GitHub][], and natively supports:

* [CryptoKit][] hash functions: [SHA-2][] (SHA-256 by default) and insecure [SHA-1][] or [MD5][];
* Fuzzy hash functions: [ssdeep][] and [TLSH][] as submodules with Swift C bridging;
* Searching for multiple digests with mixed algorithms and a similarity / distance score for fuzzy hash;
* [CDHash][] of Mach-O binaries, the identity macOS and iOS use: embedded when signed or synthesized like `syspolicyd`;
* [symhash][] of Mach-O binaries, with any algorithm, separator, and optional sort;
* [XAR][] archives (macOS packages) table of contents (TOC) checksum with any algorithm and optional decompress (zlib);
* [Git blob object][];
* Thin universal Mach-O binaries into architecture slices with exact, unsign and unpack options;
* Unsign Mach-O binaries and restore `__LINKEDIT` `vmsize`: samples signed by different identities hash the same;
* Unpack [UPX][] Mach-O binaries natively, past the signature, a crafted marker or XORed code;
* Verify Mach-O files for anomalies, as the kernel, dyld, Security, Gatekeeper, AMFI or Rosetta parse them;
* Multithreading, and zero runtime dependencies.

With `--jobs 0` or the `-J` shortcut, `fashion` is blazing fast and stays well under 100 MB of memory without `--sort`:

| Machine             | Jobs | App count |   File count    | SHA-256 duration | TLSH duration |
|:--------------------|:----:|:---------:|:---------------:|:----------------:|:-------------:|
| Mac Studio M2 Ultra |  24  | 274 apps  | 1,268,657 files |   1 min 6 secs   | 1 min 25 secs |
| MacBook Air M4      |  10  | 213 apps  |   813,217 files |        54 secs   | 1 min 42 secs |

## Install

A signed and notarized binary is available via Homebrew, cheers 🍻

```bash
brew tap melomac/tap https://codeberg.org/melomac/homebrew-tap
brew trust melomac/tap
brew install melomac/tap/fashion
```

With [melomac/tap][] mirror on GitHub, you can also just run: `brew install melomac/tap/fashion`

### Build from source

`fashion` builds with Xcode and Swift 6.2 for macOS 13 and later, its C and C++ dependencies as submodules:

```bash
git clone --recurse-submodules https://codeberg.org/melomac/fashion
cd fashion
make
```

`make test` runs the tests twice, once per `--exact` ending.
The packed fixtures require `upx` installed, and are skipped without it.

## Usage

`fashion` provides subcommands to directly access major features: `thin`, `unpack`, _etc._
Run `fashion help` to list them:

<details>
<summary>fashion help</summary>

```help
OVERVIEW: Compute and match file cryptographic or fuzzy hash digests for threat hunting and binary triage.

USAGE: fashion <subcommand>

OPTIONS:
  --version               Show the version.

SUBCOMMANDS:
  hash, h (default)       Compute and match file cryptographic or fuzzy hash digests for threat hunting and binary triage.
  thin, t, thinr          Scan Mach-O files for artifacts, each architecture and each state the flags take it through.
  unsign, i               Write and restore a Mach-O image, removing the code signature.
  unpack, p, upx          Write and restore a UPX-packed Mach-O image, unpacked without UPX.
  verify, v               Verify Mach-O files for anomalies.

  See 'fashion help <subcommand>' for detailed help.
```

</details>

`hash` is the default command, `fashion` alone is `fashion hash`:

<details>
<summary>fashion --help</summary>

```help
OVERVIEW: Compute and match file cryptographic or fuzzy hash digests for threat hunting and binary triage.

USAGE: fashion [hash] [<options>] [<paths> ...]

ARGUMENTS:
  <paths>                 Paths to scan. (default: .)

HASH MODE:
  -a, --algo <algorithm>  Hash algorithm
        md5               - MD5 insecure hash
        sha1              - SHA-1 insecure hash
        sha256            - SHA-256 hash
        sha384            - SHA-384 hash
        sha512            - SHA-512 hash
        git               - Git blob SHA-1 hash
        git256            - Git blob SHA-256 hash
        ssdeep            - Spam Sum Deep fuzzy hash
        tlsh              - Trend Micro Locality Sensitive Hash
        cdhash            - CodeDirectory hash
  -t, --thin, --slices    Hash individual Mach-O architectures.
  -e, --exact, --strict   Hash a strict Mach-O image, dropping appended bytes.
  -i, --unsign            Hash a Mach-O image, removing the code signature.
  -p, --unpack            Hash a UPX-packed Mach-O image, unpacked without UPX.
  -v, --verify            Verify Mach-O files for anomalies

MATCH MODE:
  -m, --match <match>     Digests to match.
  -s, --score <score>     Minimum similarity (ssdeep) or maximum distance (TLSH) threshold (default: 40).
  -x, --xlen              Compare TLSH digests without the recorded file length.
  -n, --negate            Print only not matched files.

SYMBOL MODE:
  --symhash, --sym        Compute SymHash (external symbol hash) for Mach-O slices.
  --separator, --sep <char>
                          Symbol separator (default: ,).
  -o, --order/--no-order  Sort symbols before hashing (default: sorted).

XAR MODE:
  --xar-toc, --xar        Hash XAR table of contents.
  -d, --dec, --decompress Decompress table of contents before hashing.

OPTIONS:
  -j, --jobs <jobs>       Number of concurrent workers (default: 1, 0 = all CPUs).
  -J                      All CPUs, short for --jobs 0.
  -L, --follow            Follow symlinks.
  -q, --quiet             Quiet mode: digest(s) or matched path(s) only.
  -S, --sort/--no-sort    Sort file paths, numbers by value. (default: --no-sort)
  --version               Show the version.
  -h, --help              Show help information.
```

</details>

## Hasher

`fashion` walks the given paths, or the current directory by default, and prints one line per regular file with the digest then the path, as the files are found or in order with `--sort` / `-S`.

`--algo` picks the hash function: `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `ssdeep`, `tlsh`, `cdhash`, `git` or `git256`, and defaults to SHA-256.

`--thin` hashes each architecture of a universal Mach-O as a file of its own.

`--exact`, `--unsign` and `--unpack` print the initial file first, unlabeled, then each artifact `thin`, `unsign` or `unpack` finds.
The digests are those of the artifacts.
**You can match any artifact with any algorithm.**

When an edit cannot be made, the file is hashed as it is and reported to standard error.
Files existing at the destination of an artifact are compared: one holding different bytes is hashed too and reported to standard error with both sizes and SHA-256s.

### Match mode

Use `--match` to search for files matching one or more digests.

Without the `--algo` option, we target several algorithms in a single pass: every file is read once and hashed with each hash function the targets need.
The shape of each target picks the hash function:

| Shape                                  | Algorithm | Shape conflict     |
|:---------------------------------------|:----------|:-------------------|
| 32 hex digits                          | `md5`     |                    |
| 40 hex digits                          | `sha1`    | `cdhash`, `git`    |
| 64 hex digits                          | `sha256`  | `cdhash`, `git256` |
| 96 hex digits                          | `sha384`  |                    |
| 128 hex digits                         | `sha512`  |                    |
| `T1` and 70 hex digits, or 70 alone    | `tlsh`    |                    |
| `blocksize:chunk:chunk`, base64 chunks | `ssdeep`  |                    |

A fuzzy match line shows the digest that matched with its score:

<details>
<summary>fashion --match</summary>

```console
$ fashion --match $(fashion --quiet --algo tlsh /usr/bin/true) /usr/bin/
T1B683F9DB67586C65EC98A97412CEE6237F33E7950FA2401760A1C4E93E437B67E3980C   40  /usr/bin/update_dyld_shared_cache
T10483D9DF1B582C51ED4C987012CEA6677F33E7950F92422B60A1C4E92E437BB6E3984C    0  /usr/bin/true
T16083DADB57582C64EC989C7412CEA727BF33E7550B92412B60A1C4EA3E437B67E3584C   26  /usr/bin/false
```

</details>

With the `-q` / `--quiet` flag, we only print matching paths.
We print non-satisfied paths with the `-n` / `--negate` flag.
`--score` sets the threshold a fuzzy match must pass, a minimum similarity for ssdeep or a maximum distance for TLSH, 40 by default.

A Code Directory hash and a Git object hash have the shape of a SHA-1 or SHA-256 digest, so matching one requires the `--algo` option.
A symhash or a XAR TOC checksum is matched in the respective mode, `--symhash` or `--xar-toc`.

### Symbol hash mode

Following the convention used by ImpHash, [symhash][], and tools like [VirusTotal][], `--symhash` mode aka `--sym`, defaults to the insecure MD5 hash of the ordered external symbol list joined by the `,` separator.
You can actually pick any algorithm (ex: `--algo ssdeep`), separator (ex: `--sep '\0'` or `--sep "\\0"` for NUL separator), and keep the symbol list as is with `--no-order`.

An image with no external symbol table reports to standard error.

With `--unpack`, the symhash goes through each artifact, one line labeled per state, and compared the same way.
`--unsign` and `--exact` change no symbol but are accepted, so one set of flags serves every mode.

### XAR TOC mode

Installation packages on macOS are eXtended ARchives.
According to [xar(1)](x-man-page://1/xar "man 1 xar"):

>xar is no longer under active development by Apple. Clients of xar should pursue alternative archive formats.

The header is straightforward so, instead of bridging to the `libxar` shared library, we implement our own parser to read the table of contents (TOC).

Just like `xar --dump-toc-cksum` and `syspolicyd`, `--xar-toc` mode defaults to the insecure SHA-1 of the compressed TOC.
You can choose any algorithm and even have the TOC decompressed (zlib) with `--decompress` / `--dec` / `-d`.

## Thinner

`fashion thin` aka `thinr` takes each architecture of a universal Mach-O as a slice, named as `lipo` spells the architecture.
The fat table alone decides the bytes of each slice, as `lipo -thin`.

`--exact`, `--unsign` and `--unpack` take universal and thinned Mach-O files through the edits hash mode makes in memory, every state on the way: the slice, then cut where the image ends, then without the code signature, then unpacked, then the unpacked image without the signature it kept.

Nothing is written, all edits happen in memory, so a tree can be looked over first: each artifact is listed as `hash` labels the state.

With `--write`, each artifact is named after the file, the architecture and what was done, ex: `ls_x86_64_unsigned_unpacked`.
A different file already under an artifact's name is kept as a backup, renamed with the suffix `~` and the current timestamp.
The backup's path is printed after the artifact's.
Anything that is not a regular file there is never replaced.

With `-q` / `--quiet`, a file that has artifacts is printed once.

## Unsigner

A sample signed again gets a new digest, though the code remains identical.
With the `--unsign` flag, we hash a Mach-O without its code signature, so samples signed by different identities hash the same.
`fashion unsign` writes that file beside the sample, `sample_unsigned`, whole: each slice of a universal file unsigned, and the file laid out again as `lipo` lays it out.

`codesign` leaves `__LINKEDIT` with the 16 KiB the signature needed, and a signed file holds no trace of what was there.
We restore `vmsize` back to its original value, as the tool that wrote the segment:

* the linker's page for an image with its symbols
* the segment's file size for an image [strip(1)](x-man-page://1/strip) cleared the symbols
* or 16 KiB for a sample stripped since Xcode 15.3, according to ld64, cctools and Security.

## Unpacker

Malware was long packed with [UPX][] on macOS, until UPX [stopped packing by default][UPX Darwin] the Darwin platform during milestone [4.2.0][UPX 4.2.0] (2023).
`upx -d` still unpacks, but gives up on samples signed after packing: code signature hides the 16-byte `__LINKEDIT` UPX left.

With the `--unpack` flag, we hash the Mach-O file as it was before packing, natively, with UPX's own [UCL][] and [LZMA][] decoders, and looking past any code signature.
`fashion unpack` writes that file beside the sample, `sample_unpacked`, whole, where `thin --unpack` writes it split.
With `--unsign`, the signature the code carried before packing comes out too.

When the marker `UPX!` was modified, or the usual section/segment was renamed, heuristics look for the `PackHeader` structure and checksum to unpack the file anyway, and report the marker we found in place.

When the packer also XORed the decompressed code before unfiltering, like [OSX/Keydnap][UPX Keydnap], the image fails its checksum: we read the XOR key off the filtered blocks.
When no key fits, the image is unpacked under none, and the sums are reported.

Unlike `upx`, we compare what comes out of the decompressor with the two Adler-32 sums the `PackHeader` carries — packed and unpacked bytes — which neither `upx -d` nor the stub reads: a sum that doesn't match is reported to standard error, and the file is unpacked all the same.
What refuses a file is: a header that doesn't hold, a block that doesn't decode, or an image that doesn't parse.

A `PackHeader` wiped out to defeat `upx -d` leaves nothing to find for us: the file is hashed as it is, unless it keeps the 16-byte `__LINKEDIT` only UPX writes, which `upx -d` and we refuse as corrupted.
UPX's `canUnpack` [comments][UPX canUnpack]...

```cpp
// Pirates might overwrite the UPX! marker.  Try harder.
```

...and falls back to emulating the entry stub and scanning for the packed data.
Anything we'd recover that way is unverifiable.

When the decompressed data isn't a Mach-O image, we hash the file like any other file.
`fashion unpack --keep` writes the decompressed data for further investigation.

We implement our own unpacker, supporting UPX 3.91 and onward:

* arm64, arm, x86_64, i386 and ppc executables;
* x86_64, i386, and ppc dylibs;
* compressed with NRV or LZMA.

## Verify

`fashion verify` lists anomalies in each Mach-O file, one line each after the file's path, and nothing about a file with nothing to report.

Each rule comes from a loader that refuses what the parser accepts: the kernel, dyld, Security, Gatekeeper, AMFI or Rosetta, stated the way that loader sees it.
The rest catch a file that two readers parse differently, which is how a sample hides from a tool.
`verify` prints one line per finding, in these groups:

* **load commands:** a count that hides the last ones, a size not a multiple of 4, a command found twice, pairs that exclude each other;
* **segments and sections:** overlapping or out of order, a file offset that disagrees with the address, `__TEXT` not first or `__LINKEDIT` not last, protections no linker writes;
* **entry point:** outside `__TEXT`, in no section, or in a thread state of another architecture;
* **linking:** a dylinker other than `/usr/lib/dyld`, `LC_DYLD_ENVIRONMENT`, no `LC_UUID`, no dylib, no symbol table, a static or non-PIE arm64 executable;
* **unaccounted bytes:** past the image, inside `__LINKEDIT` with no table over them, non-zero padding;
* **edits:** a `__LINKEDIT` `vmsize` rounded by a signature the file no longer has, UPX plain, modified or signed after packing;
* **the signature:** pages that do not hash to the code directory, a code limit short of the file, sealed blobs that do not hash to their slots, entitlements that opt out of hardening;
* **the signer:** a CMS blob that does not verify, a chain outside Apple's roots, a certificate Gatekeeper refuses, entitlements AMFI reserves to Apple;
* **universal files:** a slice hidden past the table's count, two slices of one architecture, overlapping or misaligned slices, non-zero padding.

What no loader would accept, the parser refuses: red and counted.
Most of the other findings survive an ad-hoc signature, so `codesign` still calls the file "valid on disk" while it carries hidden bytes, an inserted library, a desynced code section, or a hidden slice.

The reasoning behind each rule, the reader it comes from, the evasion it catches, and the measurements over the OS, third-party software, and a malware corpus that kept or dropped it are in [VERIFY-STRATEGY.md][VERIFY-STRATEGY.md].

`fashion --verify` and `fashion thin --verify` run the same rules, and report to the unified log under the `verify` category of the `fashion` subsystem:

<details>
<summary>log stream</summary>

```bash
log stream --style compact --predicate 'subsystem == "fashion" AND category == "verify"'
```

</details>

## Common options

### Exact

Bytes appended past a Mach-O image change its digest and keep a signature from coming out.
The `--exact` / `--strict` flag cuts a slice where the image ends, so the digest is the image's with the appended bytes dropped: the file's own digest prints first, then the cut image's, labeled `(exact)`.
Where the image ends is read as Security's strict validation reads it, at the end of the `__LINKEDIT` segment or of the `LC_SYMTAB` string table, whichever command comes first; built with `SECURITY_STRICT_VALIDATION=NO`, at the farthest byte any segment or table reaches instead, and no `--strict` alias.

### Quiet

With the `-q` / `--quiet` flag, we only print file digests, or matching paths in match mode.

### Concurrency

The `-j` / `--jobs` flag controls parallel workers.
Set `-j 0` or `-J` to use all CPU cores.

The `--sort` flag prints files in the natural order of paths: a run of digits sorts as a number, so `file-2` comes before `file-10`, and any other byte as itself, so the order holds in every locale.
The walk sorts each directory as it reads it, so hashing starts right away, and a file's lines wait until every file before it has printed.

The `-L` / `--follow` flag follows symlinks while walking; by default they are skipped.
A symlink named directly on the command line is always followed, like `find -H`.
Only regular files are hashed: a FIFO, device, or socket is skipped, whether named on the command line or in a directory.

### Colors

On a terminal, `fashion` colors lines by what they tell:

🟢 **Green**

* a full match with any algorithm: a digest, a symhash, a cdhash, `ADHOC` included;
* a fuzzy match, darker as the distance grows toward the `--score` threshold;
* TLSH distance from 300, where [false positives][TLSH paper] pass 79%, is dimmed whatever the threshold, unless `--xlen` leaves out the length those rates count;

🔴 **Red:** a malformed file in a mode that has nothing to print without parsing it: a Mach-O under `--algo cdhash`, `verify`, `unsign`, `unpack` or the edits of `thin`, a XAR under `--xar-toc`, a UPX pack `unpack` can't undo;

🟡 **Yellow:** anything else on standard error: a file that can't be read, a Mach-O or a slice that can't be parsed, an edit that can't be made, a signature that doesn't hold, a packer's marker replaced or its code XORed, a sum that doesn't match, an image with no symbol table, a file in place of an artifact that differs, or a file TLSH can't hash;

⚪️ **Dimmed:** synthesized `ADHOC` lines, for unsigned code.

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

Errors and warnings never abort the rest of the scan.

Per-path failures (a missing path, a permission-denied directory, an unreadable file, one that changed or was replaced while hashed, a name that is not UTF-8) are written to standard error and set exit code `2`.

## Hash functions

Project algorithm choices are driven by interoperability with existing tools and formats.

### CryptoKit

We use [CryptoKit][] rather than bridging to the old [Common Crypto](x-man-page://3/CC_crypto "man 3 CC_crypto") collection of C functions from `libSystem`:

>Prefer CryptoKit over lower-level interfaces.
>CryptoKit frees your app from managing raw pointers, and automatically handles tasks that make your app more secure, like overwriting sensitive data during memory deallocation.

Common Crypto's own manual page dates it:

```console
$ man 3 CC_SHA | grep HISTORY --after-context 4
HISTORY
     These functions are available in OS X 10.4 and later.

     These functions provide similar functionality to the routines found in
     OpenSSL 0.9.6 and may use the same implementation.
```

### Insecure MD5 and SHA-1

[MD5][MD5 collision] and [SHA-1][SHA-1 collision] both have known [collision attacks][collision attack].
CryptoKit files them under [Insecure][CryptoKit Insecure], so every use is visible at the call site:

> These algorithms aren’t considered cryptographically secure, but the framework provides them for backward compatibility with older services that require them.

libSystem's Common Crypto deprecates MD5 instead, which turns each call into a build warning we expressly [muted][MD5 deprecated] before adopting CryptoKit.

### ssdeep

Clang's `-Wshorten-64-to-32` warns where a 64-bit integer is stored in a 32-bit one, in case the high bits would be lost.
Xcode and SwiftPM both turn this safeguard on, and ssdeep trips it three times, in `edit_dist.c` and `fuzzy.c`, so every build of `fashion` printed warnings.
We silence the warnings in `Package.swift` for the ssdeep target only.

A spamsum chunk holds at most 64 characters, and ssdeep carries that bound everywhere.
The two values in `edit_dist.c` are positions in a chunk, 0 to 64.
The one in `fuzzy.c` caps the score of a small block size, under 45, at `block_size / 3 * minlen`, so at most 14 × 64.
A 32-bit integer holds over two billion, so the sources stay as upstream ships them.

### TLSH

Trend Micro's library counts the total data length using an `unsigned int data_len`, i.e. 32-bit, so any file larger than ~4 GB is undefined behavior.
Even worse, in Java, the code was using a signed integer (~2 GB).

We follow Trend Micro's recommendations and backport the Java fix from TLSH 4.6.0: define the TLSH of a file as the TLSH of its first ~4 GB.
The `tlsh` tool reads a file's size into a 32-bit `int` instead: it calls a file "too small" when that size modulo 4 GiB is 2 GiB or more, and hashes only that many bytes of any other.

We report on standard error each file TLSH cannot hash: under 50 bytes, with too little variation, and greater than ~4 GB ([discussion][TLSH discussion]).
Neither changes the exit status, and `--quiet` leaves them in: it shortens standard output alone.

A TLSH distance counts file length: padding, such as appended null bytes, adds to it even when the content is the same.
`--xlen` leaves the length out of `--match`, as the `tlsh` tool's `-xlen` does: a 50 KB binary padded with zeros to 2.9 MB is 1 away from itself instead of 505.

### CDHash

The CodeDirectory hash is how macOS and iOS identify an executable's integrity.
It's the hash of the directory that holds the hash of every code page.

We print the CDHash of Mach-O binaries, one line per code directory, strongest hash type first: `sha512`, `sha384`, `sha256`, `sha256t`, `sha1`.
The kernel knows no SHA-512 directory and refuses a signature that carries one, which `verify` reports.

We print the `CandidateCDHashFull` but `--match` accepts the truncated to 40 hex digits `CDHash`.

Each signed slice is checked with Security's static validation, like `codesign --verify`: every code page against its code directory, the sealed blobs against their slots, the CMS signature over the directory.
A slice that fails is labeled `INVALID`, and named on standard error without changing the exit status: "signature rejected, hashed as unsigned", or "invalid signature (code or signature have been modified)" when a byte of code changed since signing.

When `syspolicyd` meets unsigned code, it has the Security framework sign it in memory.
`fashion` computes the same digest `syspolicyd` looks up, as a dimmed `ADHOC` line.
When Security's static validation rejects the signature, `codesign` calls the file "not signed at all", and it gets its `ADHOC` line too, computed up to where the signature starts.

Mach-O files that are not code to `codesign` — object files, dSYMs, core dumps, kernel filesets — have no identity and yield no line, signed or not.

Every rule is checked against `codesign`: the tests compare `fashion`'s `ADHOC` lines with `codesign --detached -s - --identifier ADHOC` on real and crafted binaries, so a change in the Security framework fails the test rather than silently drift.

### Git hash

The `git` and `git256` algorithms compute the hash of a [Git blob object][]: `blob \(length)\0` + data.

With the digest, you can look for the object across all branches and commits of a repository:

<details>
<summary>git log --find-object</summary>

```console
$ git log --raw --all --format='%h %s' --find-object=$(fashion --algo git --quiet .swiftformat)
7f1a770 initial public release

:000000 100644 0000000 842281a A        .swiftformat
```

</details>

## Misc

### Completion

[swift-argument-parser][] provides free completion for bash, fish, and zsh:

```bash
fashion --generate-completion-script
```

With [fish-shell][], you can even source the generated completion script on demand, and it will remain for the session:

```bash
echo "fashion --generate-completion-script fish | source" > ~/.config/fish/completions/fashion.fish
```

The file holds the command rather than its output, so the completions come from the binary each time fish loads them: a flag added to a command is completed in the next shell, with nothing to regenerate.
Very convenient when you craft your own tools.

### Fuzzer

Every parser takes attacker-controlled bytes: a scan walks whatever tree it is pointed at.
Each parser has a [libFuzzer][] harness under AddressSanitizer: the fat and Mach-O headers, the code signature and its directories, the XAR header and table of contents, the symbol tables, the digests `--match` is given, the byte hashers, UPX's pack header, decoders and filters, the verifier, the CMS signer and the DER readers.

`make fuzz-run` builds them outside SwiftPM, seeds their corpora from the test fixtures and runs them all; [Fuzz/README.md][Fuzz/README.md] says what each covers and how to reproduce a finding.

### Reverse engineering

Much of what `fashion` mirrors is not documented, and was read from the binaries with [IDA Pro][] driven through [ida-mcp][]:

* the Security framework, in the dyld shared cache: how `codesign` signs, verifies and removes a signature, which code directory it reads, and what its strict validation refuses;
* `syspolicyd`: the identity Gatekeeper signs unsigned code with, and the ticket it looks up;
* dyld: what it refuses of an image it loads, and what it reads past a fat table's count;
* the kernel cache: what `parse_machfile` and `load_segment` refuse, how `cs_validate_csblob` reads a signature, what AMFI's entitlements validator takes, and what the kernel does with a thread state under Rosetta or a segment both writable and executable.

We keep their structure and names, so the two can be read side by side, and every rule taken from them is checked against the tool that enforces it.
Thanks to [Hex-Rays][] for IDA Pro, and for the MCP server that turned those reads into a conversation.

### History

The original `fashion` was a workaround for repetitive loading of the Perl command `shasum`.

The name is a mashup of my original bash function `fsha` and the David Bowie song, more specifically [the duet][fashion-youtube] with Frank Black of the Pixies.
As for the `thinr` command, the name comes from the Nightmares On Wax track, Finer, [remixed][finer-youtube] by Alex Gopher.

Python made it very easy thanks to the built-in hashlib, io, and the [python-ssdeep][] or tlsh / [py-tlsh][] modules were straightforward.
But [uv][] started [complaining][pkg_resources] about `pkg_resources`, and I needed features Python couldn't give me without significant effort.

So here we are: Swift, native, concurrent, with C and C++ dependencies bridged as submodules, and zero external runtime requirements.

## License

`fashion` is licensed under the [GNU General Public License version 3][LICENSE].

The binary includes third-party code, and [NOTICE][] carries its copyright notices and license terms:

* [ssdeep][], GPL-2.0-or-later, used under GPL-3.0;
* [TLSH][], under its BSD-3-Clause license;
* [UPX][]'s Mach-O unpacker, translated to Swift, and its [UCL][] decompressor, GPL-2.0-or-later, used under GPL-3.0;
* the [LZMA SDK][] decoder UPX uses, [LZMA][], placed in the public domain by Igor Pavlov;
* [swift-argument-parser][], Apache-2.0 with the Runtime Library Exception.

The ssdeep, TLSH, UCL and LZMA SDK sources are in the repository's submodules, with their license files, at the commits a release tag pins.

[Codeberg]: https://codeberg.org/melomac/fashion "Codeberg: melomac/fashion"
[GitHub]: https://github.com/melomac/fashion "GitHub: melomac/fashion"
[melomac/tap]: https://github.com/melomac/homebrew-tap "GitHub: melomac/homebrew-tap"

[VERIFY-STRATEGY.md]: VERIFY-STRATEGY.md
[Fuzz/README.md]: Fuzz/README.md
[LICENSE]: LICENSE
[NOTICE]: NOTICE

[CryptoKit]: https://developer.apple.com/documentation/cryptokit/ "Perform cryptographic operations securely and efficiently"
[CryptoKit Insecure]: https://developer.apple.com/documentation/cryptokit/insecure "A container for older, cryptographically insecure algorithms"
[SHA-2]: https://en.wikipedia.org/wiki/SHA-2 "Wikipedia: SHA-2"
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1 "Wikipedia: SHA-1"
[SHA-1 collision]: https://www.zdnet.com/article/sha-1-collision-attacks-are-now-actually-practical-and-a-looming-danger/ "ZDNET: SHA-1 collision attacks are now actually practical and a looming danger"
[MD5]: https://en.wikipedia.org/wiki/MD5 "Wikipedia: MD5"
[MD5 collision]: https://eprint.iacr.org/2004/199 "Collisions for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD"
[MD5 deprecated]: https://codeberg.org/melomac/fashion/src/commit/7f1a770447944ab28a0c020d5ed0f444d721b847/Sources/CMD5Wrapper/CMD5Wrapper.c#L4
[Collision attack]: https://en.wikipedia.org/wiki/Collision_attack "Wikipedia: Collision attack"
[ssdeep]: https://github.com/ssdeep-project/ssdeep "GitHub: ssdeep-project/ssdeep"
[TLSH]: https://github.com/trendmicro/tlsh "GitHub: trendmicro/tlsh"
[TLSH discussion]: https://github.com/trendmicro/tlsh/issues/84 "tlsh calculation on >2GB files causing OutOfArrayIndexException in java implementation"
[TLSH paper]: https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf "TLSH - A Locality Sensitive Hash, Tables I and II"
[CDHash]: https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes "TN3126: Inside Code Signing: Hashes"
[symhash]: https://github.com/threatstream/symhash "SymHash: An ImpHash for Mach-O"
[XAR]: https://github.com/apple-oss-distributions/xar/ "GitHub: apple-oss-distributions/xar"
[Git blob object]: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects "Git Internals - Git Objects"

[fish-shell]: https://github.com/fish-shell/fish-shell/ "The user-friendly command line shell"
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html "libFuzzer – a library for coverage-guided fuzz testing"
[IDA Pro]: https://hex-rays.com/ida-pro/ "A powerful disassembler, decompiler and a versatile debugger"
[ida-mcp]: https://hex-rays.com/blog/hex-rays-ida-mcp-server "Meet the official IDA MCP server: free, open source, and model-agnostic"
[Hex-Rays]: https://hex-rays.com "Hex-Rays: the makers of IDA Pro"
[python-ssdeep]: https://github.com/DinoTools/python-ssdeep "GitHub: DinoTools/python-ssdeep"
[py-tlsh]: https://github.com/trendmicro/tlsh/tree/master/py_ext/pypi_package "GitHub: trendmicro/tlsh Python module"
[uv]: https://docs.astral.sh/uv/ "An extremely fast Python package and project manager, written in Rust."
[pkg_resources]: https://github.com/DinoTools/python-ssdeep/pull/70/ "GitHub: DinoTools/python-ssdeep PR70"
[VirusTotal]: https://www.virustotal.com/ "Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community"

[UPX]: https://upx.github.io "UPX: the Ultimate Packer for eXecutables"
[UPX canUnpack]: https://github.com/upx/upx/blob/7c7bea44146c7ad6e17cb2d0bb9566805b44a91a/src/p_mach.cpp#L1807 "GitHub: upx/src/p_mach.cpp"
[UPX Darwin]: https://github.com/upx/upx/commit/4870765e1b304c13fd24bd0dee7f9e05e417499f "GitHub: Commit 4870765: disable packing macOS binaries for now"
[UPX Keydnap]: https://github.com/eset/malware-research/blob/master/keydnap/keydnap_upx.patch "GitHub: Add UPX patch to unpack Keydnap samples by Marc-Étienne Léveillé"
[UPX 4.2.0]: https://github.com/upx/upx/issues/686 "GitHub: UPX v4.2.0 Task List"
[UCL]: https://github.com/upx/upx-vendor-ucl/tree/upx-vendor "UCL is a portable lossless data compression library written in ANSI C"
[LZMA]: https://github.com/upx/upx-vendor-lzma-sdk/tree/upx-vendor "Lempel–Ziv–Markov chain algorithm"
[LZMA SDK]: https://www.7-zip.org/sdk.html "The LZMA SDK provides the documentation, samples, header files, libraries, and tools you need to develop applications that use LZMA compression"
[swift-argument-parser]: https://github.com/apple/swift-argument-parser "Straightforward, type-safe argument parsing for Swift"

[fashion-youtube]: https://www.youtube.com/watch?v=3I-4ck0NXwA&t=928s "David Bowie & Friends: A Very Special Birthday Celebration Concert NYC 1997"
[finer-youtube]: https://www.youtube.com/watch?v=baGz8npW0vs "Nightmares On Wax official, Finer \(Alex Gopher Mix\)"
