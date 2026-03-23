# fashion

Swift command-line interface to traverse a file hierarchy and compute or match popular hash digests. The project natively supports:

* [CryptoKit](https://developer.apple.com/documentation/cryptokit/ "Perform cryptographic operations securely and efficiently.") hash functions: [SHA-2][] (SHA256 by default), insecure [SHA-1][] and [MD5][]
* fuzzy hash functions: [SSDeep][] and [TLSH][] as submodules with Swift C bridging
* searching for multiple digests with any algo and a similarity / distance score for fuzzy hash
* [git-hash-object][]
* [symhash][] with any algo, separator and optional sort (Mach-O binaries)
* [XAR][] archives (macOS packages) table of contents checksum with any algo and optional decompress (zlib)
* [CDHash][] (signed Mach-O binaries)
* multithreading

With optimizations, `fashion` is very fast yet has a minimal real memory footprint < 150MB:

| Machine             | App count | File count    | SHA256 time | TLSH time        |
|:--------------------|:---------:|:-------------:|:-----------:|:----------------:|
| Mac Studio M2 Ultra | 292 apps  | 910,000 files |  1 minute   |    2 minutes     |
| MacBook Air M4      | 231 apps  | 720,000 files | 42 seconds  | 1 minute 30 secs |

## Features

### Supported algorithm

Project algorithm choices are driven by interoperability with existing tools and formats.

[SHA-2]: https://en.wikipedia.org/wiki/SHA-2 "Wikipedia: SHA-2"
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1 "Wikipedia: SHA-1"
[MD5]: https://en.wikipedia.org/wiki/MD5 "Wikipedia: MD5"
[SSDeep]: https://github.com/ssdeep-project/ssdeep "GitHub: ssdeep-project/ssdeep"
[TLSH]: https://github.com/trendmicro/tlsh "GitHub: trendmicro/tlsh"
[Git-Hash-object]: https://git-scm.com/docs/git-hash-object "Git: hash-object"
[SymHash]: https://www.anomali.com/blog/symhash "SymHash: An ImpHash for Mach-O"
[XAR]: https://github.com/apple-oss-distributions/xar/ "GitHub: apple-oss-distributions/xar"
[CDHash]: https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes "TN3126: Inside Code Signing: Hashes"

#### Insecure MD5 and SHA1

MD5 and SHA1 both have known [collisions](https://en.wikipedia.org/wiki/Collision_attack#cite_note-md5-2004-1) and are considered insecure.

#### TLSH

Trend Micro library counts the total data length using an `unsigned int data_len` i.e. 32-bit, so any file larger than ~4GB is undefined behavior. Even worse, on Java, the code was using a signed integer (~2GB).

`fashion` follows Trend Micro recommendations and backports the Java fix from TLSH 4.6.0 to define the TLSH of a file as the TLSH of its first ~4GB.

#### Git hash

The `git` and `git256` algo compute the hash of a [Git](https://git-scm.com/) blob object. With the hash, you can look for the object across all branches and commits of a repository.

```console
$ git log --raw --all --format='%h %s' --find-object=$(fashion --algo git --quiet .swiftformat)
7f1a770 initial public release

:000000 100644 0000000 842281a A        .swiftformat
```

#### CDHash

Compute the Code Directory hash of signed Mach-O binaries, according to the strongest supported hash (usually SHA256). While we print the full hash, we can match both CDHashFull and truncated CDHash.

### Quiet flag

With the `-q` / `--quiet` flag, we only print file digests.

### Match mode

Use `-m` / `--match` to search for files matching one or more digests.

```console
$ fashion --algo tlsh --match $(fashion --quiet --algo tlsh /usr/bin/true) /usr/bin/
T1B683F9DB67586C65EC98A97412CEE6237F33E7950FA2401760A1C4E93E437B67E3980C   40  /usr/bin/update_dyld_shared_cache
T10483D9DF1B582C51ED4C987012CEA6677F33E7950F92422B60A1C4E92E437BB6E3984C    0  /usr/bin/true
T16083DADB57582C64EC989C7412CEA727BF33E7550B92412B60A1C4EA3E437B67E3584C   26  /usr/bin/false
```

With the quiet flag, we only print matching paths.

### Symbol mode

Following the convention used by ImpHash, symhash, and tools like [VirusTotal](https://www.virustotal.com/), `--symhash` mode defaults to MD5 of the ordered external symbols list joined by the `,` separator, but you can pick any algo, separator, and keep the symbols list as is.

```console
$ fashion --symhash --algo ssdeep --match $(fashion --symhash --algo ssdeep admobs.ru/agent/bin/Pods --quiet) admobs.ru
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/agent/bin/cat
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/agent/bin/Pods
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/sys/bin/Pods
6:vILFGL4MPEm03Jc6DVXYtZPGujVpEKK7XBUL9xMw:vIJMgqIXYTnhpEKK7X8xMw  100  admobs.ru/d
```

### XAR mode

Installation packages on macOS. According to [xar(1)](x-man-page://1/xar "man 1 xar"):

>xar is no longer under active development by Apple. Clients of xar should pursue alternative archive formats.

eXtended ARchive header is straightforward, so we implement our own parser to read the table of contents (TOC) instead of bridging the library.

Just like `xar --dump-toc-cksum`, `--xar-toc` mode defaults to SHA1 of the compressed TOC, but you can choose any algo and even have the TOC decompressed (zlib).

### Mach-O support

`fashion` parses universal and thin Mach-O binaries natively. The `--slices` flag hashes each architecture individually in addition to the whole file. Supported architectures: `arm64`, `arm64e`, `x86_64`, `i386`, and legacy `ppc` / `ppc64`.

### Concurrency

The `-j` / `--jobs` flag controls parallel workers. Set `-j 0` to use all available CPU cores.

The `--sort` flag trades some throughput for deterministic output order—paths are collected, sorted, and results are emitted sequentially even under concurrent processing.

## Misc

### Completion

[swift-argument-parser](https://github.com/apple/swift-argument-parser "Straightforward, type-safe argument parsing for Swift") provides free completion for bash, fish and zsh:

```bash
fashion --generate-completion-script
```

With [fish-shell](https://github.com/fish-shell/fish-shell/ "The user-friendly command line shell."), you can even source the generated completion script on-demand, and it will remain for the session:

```bash
echo "fashion --generate-completion-script fish | source" > ~/.config/fish/completions/fashion.fish
```

Very convenient when you craft your own tools.

### History

The original `fashion` was a workaround for repetitive loading of the Perl command `shasum`.

The name is a mashup between my original bash function `fsha` and the David Bowie song, more specifically [the duo](https://www.youtube.com/watch?v=3I-4ck0NXwA&t=928s "David Bowie & Friends: A Very Special Birthday Celebration Concert NYC 1997") with Frank Black from The Pixies.

Python made it very easy thanks to built-in hashlib, io, and [python-ssdeep](https://github.com/DinoTools/python-ssdeep "GitHub: DinoTools/python-ssdeep") or tlsh / [py-tlsh](https://github.com/trendmicro/tlsh/tree/master/py_ext/pypi_package "GitHub: trendmicro/tlsh Python module") modules were straightforward. But [uv](https://docs.astral.sh/uv/ "An extremely fast Python package and project manager, written in Rust.") was [complaining](https://github.com/DinoTools/python-ssdeep/pull/70/changes#diff-60f61ab7a8d1910d86d9fda2261620314edcae5894d5aaa236b821c7256badd7R8 "GitHub: DinoTools/python-ssdeep PR70") about pkg_resources, and I needed features Python couldn't give me without significant effort.

So here we are: Swift, native, concurrent, with C and C++ dependencies bridged as submodules, and zero external runtime requirements.
