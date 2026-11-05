#!/bin/bash
#
# fashion's fuzzing harness (see README.md): libFuzzer entry points over the parsers, built with -sanitize=fuzzer,address
# outside SwiftPM, which lets no executable depend on the fashion target.
#
#   Fuzz/fuzz.sh build            build .build/fuzz/bin/fuzz-* from Sources/, Bridges/ and the harnesses here
#   Fuzz/fuzz.sh seed             seed .build/fuzz/corpus/* from the test fixtures, /bin/ls and a XAR, the corpora
#                                 grown so far merged in
#   Fuzz/fuzz.sh run [seconds] [harness...]   run the harnesses named, all by default, for that long (900) each, FUZZ_JOBS
#                                             processes each (2), respawned as they die, in waves of equal size that
#                                             the cores hold, each reported as it ends
#   Fuzz/fuzz.sh summary [harness...]         what the last run did: runs, executions per second, coverage, artifacts
#   Fuzz/fuzz.sh watch [harness...]           follow the logs of a run as they are written, waves to come included
#   Fuzz/fuzz.sh merge [tree] [harness...]    merge another tree's corpora into these, or these into themselves,
#                                             keeping what reaches an edge the rest does not
#   Fuzz/fuzz.sh clean            remove what seed and run wrote, corpora, logs and artifacts; the binaries stay
#
# FUZZ_BUILD names the tree, .build/fuzz by default, which make distclean removes with the rest of .build: a
# directory outside the repository outlives it.
#
set -eo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${FUZZ_BUILD:-$root/.build/fuzz}
swiftpm=$build/swiftpm
bin=$build/bin
corpus=$build/corpus
artifacts=$build/artifacts
logs=$build/logs
# Processes per binary, and the cores they run on: run launches the binaries in waves of equal size, no larger than
# the cores hold, cores / jobs, so the processes never outnumber the cores (libFuzzer's -timeout counts wall time:
# oversubscribed, a slow unit passes for a hung one). FUZZ_CORES=$(sysctl -n hw.perflevel0.logicalcpu) keeps the
# efficiency cores out of it.
jobs=${FUZZ_JOBS:-2}
cores=${FUZZ_CORES:-$(sysctl -n hw.ncpu)}

# The harnesses: each is Fuzz/<name>.swift, with an LLVMFuzzerTestOneInput, and fuzzes corpus/<name>.
harnesses="macho cdhash xar symhash diff bytehash unpack decompress verify signer der"

# The --exact endings a harness is built with (see Package.swift): both for those that read a Mach-O's logical end.
endings() {
    case $1 in
        macho | cdhash | unpack | verify) echo "strict segments" ;;
        *) echo strict ;;
    esac
}

# The binaries `build` makes, one per harness and ending: every harness's, or those named.
binaries() {
    local harness ending
    for harness in ${*:-$harnesses}; do
        for ending in $(endings "$harness"); do
            if [ "$ending" = segments ]; then
                echo "fuzz-$harness-segments"
            else
                echo "fuzz-$harness"
            fi
        done
    done
}

# The longest input a harness takes: a signed /bin/ls slice, a XAR, two digests, a superblob.
max_len() {
    case $1 in
        macho | cdhash | symhash | unpack | verify) echo 262144 ;;
        diff) echo 512 ;;
        *) echo 65536 ;;
    esac
}

# The largest single allocation a harness may make before libFuzzer calls it a finding. A pack info may claim an image
# of up to the 768 MiB UPX allows (PackMach.maxSize), which unpack() allocates before it decodes a block and fashion
# then rejects in milliseconds, the buffer never touched: under that ceiling the claim is the limit at work, not a bug.
malloc_limit() {
    case $1 in
        unpack) echo 1024 ;;
        *) echo 512 ;;
    esac
}

# Whether $1 is missing or older than any of the other files.
stale() {
    local out=$1
    shift
    [ ! -e "$out" ] || [ -n "$(find "$@" -newer "$out" | head -1)" ]
}

# libFuzzer's runtime. Xcode's toolchain ships ASan's but not libFuzzer's, and swiftc refuses -sanitize=fuzzer without
# it, so the instrumentation flag goes straight to the frontend and the archive comes from the toolchain when it has one,
# else from Homebrew's LLVM (brew install llvm).
fuzzer_runtime() {
    local lib
    for lib in "$(dirname "$(dirname "$(xcrun --find clang)")")"/lib/clang/*/lib/darwin/libclang_rt.fuzzer_osx.a \
        "$(brew --prefix llvm 2>/dev/null)"/lib/clang/*/lib/darwin/libclang_rt.fuzzer_osx.a; do
        if [ -f "$lib" ]; then
            echo "$lib"
            return
        fi
    done
    echo "libclang_rt.fuzzer_osx.a not found in the toolchain or Homebrew's LLVM: brew install llvm" >&2
    exit 1
}

build() {
    local runtime
    runtime=$(fuzzer_runtime)

    # The products are remade when their sources are newer, which a toolchain update leaves as they are, though a
    # module built under one SDK or compiler is refused by the next. The compiler and the SDK are stamped in the
    # tree, and everything built goes when the stamp changes; the corpora, logs and artifacts stay.
    local toolchain
    toolchain=$(xcrun swiftc -version 2>&1 | head -1; xcrun -sdk macosx --show-sdk-version)
    if [ "$(cat "$build/toolchain" 2>/dev/null)" != "$toolchain" ]; then
        rm -rf "$build/modules" "$build/objects" "$build/strict" "$build/segments" "${bin:?}"
        mkdir -p "$build"
        echo "$toolchain" > "$build/toolchain"
    fi
    mkdir -p "$build/modules" "$build/objects" "$bin"

    # swiftc as SwiftPM runs it for the package, plus the sanitizers for the code under test.
    local swift=(xcrun swiftc -O -g -parse-as-library -swift-version 6 -target "$(uname -m)-apple-macos13.0")
    local sanitize=(-sanitize=address -Xfrontend -sanitize=fuzzer,address)
    local includes=(-I "$build/modules" -I "$build/modules/CSSDeep" -I "$build/modules/CTLSH" -I "$build/modules/CMachOCompat")

    # ArgumentParser, which the CLI imports, from the checkout SwiftPM resolves; it is not what is fuzzed, so it is
    # neither instrumented nor sanitized.
    local ap=$swiftpm/checkouts/swift-argument-parser/Sources
    if [ ! -d "$ap" ]; then
        xcrun swift package resolve --package-path "$root" --scratch-path "$swiftpm"
    fi
    local files=() file
    if stale "$build/objects/ArgumentParserToolInfo.o" "$ap/ArgumentParserToolInfo"; then
        "${swift[@]}" -c -wmo -module-name ArgumentParserToolInfo -emit-module -emit-module-path "$build/modules/ArgumentParserToolInfo.swiftmodule" "$ap"/ArgumentParserToolInfo/*.swift -o "$build/objects/ArgumentParserToolInfo.o"
    fi
    if stale "$build/objects/ArgumentParser.o" "$ap/ArgumentParser"; then
        while IFS= read -r -d '' file; do
            files+=("$file")
        done < <(find "$ap/ArgumentParser" -name '*.swift' -print0)
        "${swift[@]}" -c -wmo -module-name ArgumentParser -I "$build/modules" -emit-module -emit-module-path "$build/modules/ArgumentParser.swiftmodule" "${files[@]}" -o "$build/objects/ArgumentParser.o"
    fi

    # The C targets, with the module maps SwiftPM writes for them, instrumented too: ssdeep, TLSH and UPX's decoders
    # read the bytes. The bridges to the submodules are in Bridges/, fashion's own C in Sources/.
    local name include header cflags=(-c -O1 -g -fsanitize=fuzzer-no-link,address -target "$(uname -m)-apple-macos13.0")
    for name in Bridges/CSSDeep Bridges/CTLSH Bridges/CUCL Bridges/CLZMA Sources/CMachOCompat; do
        include=$root/$name/include
        name=$(basename "$name")
        mkdir -p "$build/modules/$name"
        header=$include/$name.h
        if [ -f "$header" ]; then
            printf 'module %s {\n    umbrella header "%s"\n    export *\n}\n' "$name" "$header" > "$build/modules/$name/module.modulemap"
        else
            printf 'module %s {\n    umbrella "%s"\n    export *\n}\n' "$name" "$include" > "$build/modules/$name/module.modulemap"
        fi
    done
    for file in "$root"/Bridges/CSSDeep/*.c "$root"/Sources/CMachOCompat/*.c; do
        name=$build/objects/$(basename "$file" .c).o
        if stale "$name" "$file" "$(dirname "$file")/include" "$root/submodules/ssdeep"; then
            xcrun clang "${cflags[@]}" -I "$(dirname "$file")/include" "$file" -o "$name"
        fi
    done
    for file in "$root"/Bridges/CUCL/*.c "$root"/Bridges/CLZMA/*.c; do
        name=$build/objects/$(basename "$file" .c).o
        if stale "$name" "$file" "$root/submodules/ucl" "$root/submodules/lzma-sdk"; then
            xcrun clang "${cflags[@]}" -I "$root/submodules/ucl/include" -I "$root/submodules/ucl" "$file" -o "$name"
        fi
    done
    for file in "$root"/Bridges/CTLSH/*.cpp; do
        name=$build/objects/$(basename "$file" .cpp).o
        if stale "$name" "$file" "$root/Bridges/CTLSH/include" "$root/submodules/tlsh"; then
            xcrun clang++ "${cflags[@]}" -DBUCKETS_128 -DCHECKSUM_1B -I "$root/Bridges/CTLSH/include" -I "$root/submodules/tlsh/include" "$file" -o "$name"
        fi
    done

    # The fashion module itself, once per --exact ending, as SwiftPM builds it for the tests: testable, and its entry
    # point renamed so that libFuzzer's main links.
    local ending define out
    for ending in strict segments; do
        out=$build/$ending
        mkdir -p "$out"
        if stale "$out/fashion.o" "$root/Sources/fashion"; then
            define=()
            if [ "$ending" = strict ]; then
                define=(-D SECURITY_STRICT_VALIDATION)
            fi
            "${swift[@]}" "${sanitize[@]}" ${define[@]+"${define[@]}"} -c -wmo -enable-testing -module-name fashion \
                -Xfrontend -entry-point-function-name -Xfrontend fashion_main "${includes[@]}" \
                -emit-module -emit-module-path "$out/fashion.swiftmodule" \
                "$root"/Sources/fashion/*.swift "$root"/Sources/fashion/Algorithms/*.swift "$root"/Sources/fashion/Bridges/*.swift "$root"/Sources/fashion/Commands/*.swift "$root"/Sources/fashion/MachO/*.swift -o "$out/fashion.o"
        fi
    done

    # One binary per harness and ending.
    local harness
    for name in $(binaries); do
        harness=${name#fuzz-}
        harness=${harness%-segments}
        out=$build/strict
        if [ "$name" != "${name%-segments}" ]; then
            out=$build/segments
        fi
        if stale "$bin/$name" "$root/Fuzz/support.swift" "$root/Fuzz/$harness.swift" "$out/fashion.o" "$build/objects"; then
            "${swift[@]}" "${sanitize[@]}" -module-name "fuzz_$harness" -I "$out" "${includes[@]}" \
                "$root/Fuzz/support.swift" "$root/Fuzz/$harness.swift" "$out/fashion.o" "$build"/objects/*.o \
                -Xlinker "$runtime" -lc++ -o "$bin/$name"
        fi
    done
    binaries
}

seed() {
    local harness
    # The corpora are seeded beside their name and moved into it once whole, so that a seeding that fails leaves no
    # corpus for a later run to take as complete; the corpora grown so far are merged into the seeded ones first,
    # their gains kept and their bulk dropped. The fixtures are made again; the logs and artifacts stay.
    local final=$corpus
    corpus=$final.seeding
    rm -rf "$corpus" "${build:?}/fixtures" "$build/seed-test.log"
    mkdir -p "$build/fixtures"
    for harness in $harnesses; do
        mkdir -p "$corpus/$harness"
    done

    # Every fixture the tests open, hand-built, compiled or codesigned (FASHION_FIXTURES, see TestHelpers.swift).
    echo "Running the tests to collect their fixtures (see $build/seed-test.log)..."
    FASHION_FIXTURES=$build/fixtures xcrun swift test --package-path "$root" --scratch-path "$swiftpm" > "$build/seed-test.log" 2>&1 ||
        echo "swift test failed; the fixtures it did write are used"

    # The OS's own universal binary, whole and by slice, and a XAR of this directory.
    cp /bin/ls "$build/fixtures/bin-ls"
    local arch
    for arch in $(lipo -archs /bin/ls); do
        lipo -thin "$arch" /bin/ls -output "$build/fixtures/bin-ls-$arch"
    done
    (cd "$root" && xar -cf "$build/fixtures/fuzz.xar" Fuzz)

    # Sorted by magic: Mach-O and fat files to the Mach-O harnesses, XARs to xar, everything to bytehash.
    local file
    for file in "$build"/fixtures/*; do
        case $(od -An -tx1 -N4 "$file" | tr -d ' ') in
            cffaedfe | feedfacf | cefaedfe | feedface | cafebabe | cafebabf)
                for harness in macho cdhash symhash unpack verify; do
                    cp "$file" "$corpus/$harness/"
                done
                ;;
            78617221)
                cp "$file" "$corpus/xar/"
                ;;
            30* | 70*)
                # DER as it is: a SEQUENCE, a CMS signature the verifier tests made, or a DER property list.
                cp "$file" "$corpus/der/"
                ;;
        esac
        cp "$file" "$corpus/bytehash/"
    done

    # The blocks of the packed images, each as the decompress harness takes it: its b_info's method, size, filter and
    # cto, then its data. The pack header's overlay offset finds the p_info, the blocks follow it, each after the last.
    local packed
    for packed in "$corpus"/unpack/*; do
        xcrun python3 -I - "$packed" "$corpus/decompress" <<'PYTHON'
import hashlib, struct, sys
data, out = open(sys.argv[1], "rb").read(), sys.argv[2]
header = data.rfind(b"UPX!")
if header < 0 or header + 36 > len(data):
    sys.exit()
at = struct.unpack_from("<I", data, header + 32)[0] + 12
while at + 12 <= len(data):
    size, packed = struct.unpack_from("<ii", data, at)
    method, filter, cto = data[at + 8], data[at + 9], data[at + 10]
    if size <= 0 or packed <= 0 or packed > size or at + 12 + packed > len(data):
        break
    if method == 0:  # stored as it is, nothing to decode
        at += 12 + packed
        continue
    block = bytes([method]) + min(size, 1 << 20).to_bytes(3, "little") + bytes([filter, cto]) + data[at + 12 : at + 12 + packed]
    open(f"{out}/{hashlib.sha256(block).hexdigest()}", "wb").write(block)
    at += 12 + packed
PYTHON
    done

    # The embedded signatures of the Mach-O fixtures, each slice's superblob as LC_CODE_SIGNATURE points at it, for
    # the signer harness: the code directory and the CMS blob that signs it, together.
    local image
    for image in "$corpus"/verify/*; do
        xcrun python3 -I - "$image" "$corpus/signer" <<'PYTHON'
import hashlib, struct, sys
data, out = open(sys.argv[1], "rb").read(), sys.argv[2]

def superblob(base, end):
    """The superblob of the image at base, cut to the length its header declares, when it has one that fits."""
    if base + 32 > end:
        return
    magic = struct.unpack_from(">I", data, base)[0]
    little, bits = {0xCFFAEDFE: ("<", 64), 0xCEFAEDFE: ("<", 32), 0xFEEDFACF: (">", 64), 0xFEEDFACE: (">", 32)}.get(magic, (None, 0))
    if not little:
        return
    ncmds = struct.unpack_from(little + "I", data, base + 16)[0]
    at = base + (32 if bits == 64 else 28)
    for _ in range(ncmds):
        if at + 8 > end:
            return
        cmd, cmdsize = struct.unpack_from(little + "II", data, at)
        if cmdsize < 8 or at + cmdsize > end:
            return
        if cmd == 0x1D and cmdsize >= 16:  # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from(little + "II", data, at + 8)
            blob = data[base + dataoff : base + dataoff + datasize]
            if len(blob) >= 12 and blob[:4] == b"\xfa\xde\x0c\xc0":
                blob = blob[: struct.unpack_from(">I", blob, 4)[0]]
                open(f"{out}/{hashlib.sha256(blob).hexdigest()}", "wb").write(blob)
            return
        at += cmdsize

if len(data) < 8:
    sys.exit()
if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
    wide = data[:4] == b"\xca\xfe\xba\xbf"
    count = struct.unpack_from(">I", data, 4)[0]
    for index in range(min(count, 64)):
        entry = 8 + index * (32 if wide else 20)
        if entry + (32 if wide else 20) > len(data):
            break
        offset, size = struct.unpack_from(">QQ" if wide else ">II", data, entry + 8)
        if offset + size <= len(data):
            superblob(offset, offset + size)
else:
    superblob(0, len(data))
PYTHON
    done

    # The DER each superblob carries, for the der harness: its CMS blob and its DER entitlements, without their blob
    # headers, as `Signer` and `DEREntitlements` take them.
    local superblob
    for superblob in "$corpus"/signer/*; do
        xcrun python3 -I - "$superblob" "$corpus/der" <<'PYTHON'
import hashlib, struct, sys
data, out = open(sys.argv[1], "rb").read(), sys.argv[2]
count = struct.unpack_from(">I", data, 8)[0] if len(data) >= 12 else 0
for index in range(min(count, 64)):
    if 20 + index * 8 > len(data):
        break
    slot, offset = struct.unpack_from(">II", data, 12 + index * 8)
    if slot not in (0x10000, 7) or offset + 8 > len(data):  # the CMS blob, the DER entitlements
        continue
    blob = data[offset + 8 : offset + struct.unpack_from(">I", data, offset + 4)[0]]
    if blob:
        open(f"{out}/{hashlib.sha256(blob).hexdigest()}", "wb").write(blob)
PYTHON
    done

    # Digests to compare, from the fashion the tests built: each against the other, and against itself.
    local fashion digests first second algorithm
    fashion=$(xcrun swift build --package-path "$root" --scratch-path "$swiftpm" --show-bin-path)/fashion
    for algorithm in tlsh ssdeep; do
        digests=$("$fashion" -q -a "$algorithm" /bin/ls "$root/Sources/fashion/MachO/MachO.swift")
        first=$(echo "$digests" | sed -n 1p)
        second=$(echo "$digests" | sed -n 2p)
        printf '%s\0%s' "$first" "$second" > "$corpus/diff/$algorithm-pair"
        printf '%s' "$first" > "$corpus/diff/$algorithm-same"
    done

    if [ -d "$final" ]; then
        echo "Merging the corpora grown so far into the seeded ones..."
        merge "$final"
        rm -rf "$final"
    fi
    mv "$corpus" "$final"
    corpus=$final
    for harness in $harnesses; do
        echo "$corpus/$harness: $(ls "$corpus/$harness" | wc -l | tr -d ' ') files"
    done
}

# The corpora of another tree, $1 (its corpus/<harness>, or <harness> under it), merged into these: libFuzzer runs
# each of its units once under each binary of the harness and keeps those that reach an edge the corpus here does
# not, so a tree's gains move without its bulk. Without a tree, each corpus is merged into an empty one that takes
# its place: minimized. Edges alone decide, not the comparison operands value profiling keeps, which a run finds
# again within its first minute; a unit that crashes or times out is left out and its artifact written.
merge() {
    local from=${1:-} harness name source target before count
    if [ -n "$from" ]; then
        shift
        if [ -d "$from/corpus" ]; then
            from=$from/corpus
        fi
    fi
    mkdir -p "$logs"
    for harness in ${*:-$harnesses}; do
        if [ -n "$from" ]; then
            source=$from/$harness
            target=$corpus/$harness
            [ -d "$source" ] || continue
            mkdir -p "$target"
        else
            source=$corpus/$harness
            target=$source.merging
            rm -rf "$target"
            mkdir -p "$target"
        fi
        before=$(ls "$target" | wc -l | tr -d ' ')
        count=$(ls "$source" | wc -l | tr -d ' ')
        for name in $(binaries "$harness"); do
            mkdir -p "$artifacts/$name"
            "$bin/$name" -merge=1 -max_len="$(max_len "$harness")" -rss_limit_mb=2048 -malloc_limit_mb="$(malloc_limit "$harness")" \
                -artifact_prefix="$artifacts/$name/" "$target" "$source" > "$logs/merge-$name.log" 2>&1 ||
                echo "merging $source under $name failed, see $logs/merge-$name.log" >&2
        done
        if [ -n "$from" ]; then
            echo "$target: $(($(ls "$target" | wc -l | tr -d ' ') - before)) of $source's $count units added"
        else
            rm -rf "$source"
            mv "$target" "$source"
            echo "$source: $(ls "$source" | wc -l | tr -d ' ') of its $count units kept"
        fi
    done
}

run() {
    # The seconds are optional, a number; what follows names the harnesses.
    local seconds=900 name harness dict count
    case ${1:-} in
        '' | *[!0-9]*) ;;
        *)
            seconds=$1
            shift
            ;;
    esac
    for harness in "$@"; do
        case " $harnesses " in
            *" $harness "*) ;;
            *)
                echo "no harness named $harness; there are: $harnesses" >&2
                exit 2
                ;;
        esac
    done
    if [ ! -d "$corpus" ]; then
        seed
    fi
    # The binaries go in waves no larger than the cores hold, cores / jobs, and as equal as the count allows, each
    # wave waited for before the next starts: the processes never outnumber the cores, and no wave leaves most of
    # them idle; a jobs past the cores gets a binary at a time, and a warning.
    local slots=$((cores / jobs)) count waves per
    if [ "$slots" -lt 1 ]; then
        slots=1
        echo "warning: $jobs processes on $cores cores; set FUZZ_JOBS lower" >&2
    fi
    local all=($(binaries "$@")) wave=1 i
    count=${#all[@]}
    waves=$(((count + slots - 1) / slots))
    per=$(((count + waves - 1) / waves))
    echo "Running ${*:-every harness}: $count binaries, $waves waves of up to $per, $jobs processes each, $seconds seconds a wave..."
    for ((i = 0; i < count; i += per)); do
        local names=("${all[@]:i:per}")
        echo "wave $wave of $waves, until about $(date -v "+${seconds}S" '+%H:%M'): ${names[*]}"
        for name in "${names[@]}"; do
            harness=${name#fuzz-}
            harness=${harness%-segments}
            dict=()
            if [ -f "$root/Fuzz/$harness.dict" ]; then
                dict=(-dict="$root/Fuzz/$harness.dict")
            fi
            rm -rf "${logs:?}/${name:?}"
            mkdir -p "$artifacts/$name" "$logs/$name"
            # libFuzzer's fork mode: the parent spawns jobs processes over and over, each fuzzing a while from the
            # corpus and merging what it found back, so one that dies of memory or a timeout is replaced, its input
            # written as an artifact and counted, where a crash ends the binary's run with its artifact. The parent's
            # log is the one read back; the jobs' own live in a temporary directory, gone with them.
            (cd "$logs/$name" && "$bin/$name" -fork="$jobs" -max_total_time="$seconds" -timeout=10 \
                -rss_limit_mb=2048 -malloc_limit_mb="$(malloc_limit "$harness")" -use_value_profile=1 \
                -max_len="$(max_len "$harness")" ${dict[@]+"${dict[@]}"} -artifact_prefix="$artifacts/$name/" \
                "$corpus/$harness" > "$name.log" 2>&1) &
        done
        wait
        for name in "${names[@]}"; do
            report "$name"
        done
        wave=$((wave + 1))
    done
}

# What the last run of one binary did, from its log (<binary>.log, the parent's): its last status line carries the
# runs so far, the edges reached and the seconds elapsed, and the rate is the runs over the seconds, all processes
# together.
report() {
    local name=$1 line runs cov seconds rate found
    [ -f "$logs/$name/$name.log" ] || return 0
    line=$(grep '^#[0-9]*: cov: ' "$logs/$name/$name.log" | tail -1)
    runs=$(echo "$line" | sed -n 's/^#\([0-9]*\):.*/\1/p')
    cov=$(echo "$line" | sed -n 's/.* cov: \([0-9]*\).*/\1/p')
    seconds=$(echo "$line" | sed -n 's/.* time: \([0-9]*\)s.*/\1/p')
    rate=$((${runs:-0} / (${seconds:-0} > 0 ? seconds : 1)))
    found=$(ls "$artifacts/$name" 2>/dev/null | wc -l | tr -d ' ')
    printf '%-24s %12s runs %8s exec/s  cov %-6s artifacts %s\n' "$name" "${runs:-0}" "$rate" "${cov:-0}" "$found"
    ls "$artifacts/$name" 2>/dev/null | sed 's/^/    /'
}

# The logs of a run followed as they grow, each binary's, named before they exist: tail -F follows names and takes a
# file up when it appears, as a later wave's do, or when run makes a binary's log directory again to launch it. A
# glob would name the files of the moment only.
watch() {
    local name files=()
    for name in $(binaries "$@"); do
        files+=("$logs/$name/$name.log")
    done
    exec tail -F "${files[@]}"
}

# What the last run did, binary by binary: every harness's, or those named.
summary() {
    local name
    for name in $(binaries "$@"); do
        report "$name"
    done
}

# Back to a built tree: the corpora and what they gained, a seeding of them left unfinished, the fixtures they were
# seeded from, the logs and the artifacts go, so the next run seeds afresh and reports its own findings alone; the
# binaries stay, as building them is the slow part.
clean() {
    rm -rf "${corpus:?}" "$corpus.seeding" "${build:?}/fixtures" "$build/seed-test.log" "${logs:?}" "${artifacts:?}"
}

case ${1:-} in
    build | seed | run | summary | watch | merge | clean)
        "$@"
        ;;
    *)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
