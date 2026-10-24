#!/bin/bash
#
# fashion's fuzzing harness (see README.md): libFuzzer entry points over the parsers, built with -sanitize=fuzzer,address
# outside SwiftPM, which lets no executable depend on the fashion target.
#
#   Fuzz/fuzz.sh build            build .build/fuzz/bin/fuzz-* from Sources/, Bridges/ and the harnesses here
#   Fuzz/fuzz.sh seed             seed .build/fuzz/corpus/* from the test fixtures, /bin/ls and a XAR
#   Fuzz/fuzz.sh run [seconds]    run every harness for that long (900 by default), FUZZ_JOBS workers each (2)
#   Fuzz/fuzz.sh summary          what the last run did: runs, executions per second, coverage, artifacts
#
set -eo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=${FUZZ_BUILD:-$root/.build/fuzz}
swiftpm=$build/swiftpm
bin=$build/bin
corpus=$build/corpus
artifacts=$build/artifacts
logs=$build/logs
jobs=${FUZZ_JOBS:-2}

# The harnesses: each is Fuzz/<name>.swift, with an LLVMFuzzerTestOneInput, and fuzzes corpus/<name>.
harnesses="macho cdhash xar symhash diff bytehash unpack"

# The --exact endings a harness is built with (see Package.swift): both for those that read a Mach-O's logical end.
endings() {
    case $1 in
        macho | cdhash | unpack) echo "strict segments" ;;
        *) echo strict ;;
    esac
}

# The binaries `build` makes: one per harness and ending.
binaries() {
    local harness ending
    for harness in $harnesses; do
        for ending in $(endings "$harness"); do
            if [ "$ending" = segments ]; then
                echo "fuzz-$harness-segments"
            else
                echo "fuzz-$harness"
            fi
        done
    done
}

# The longest input a harness takes: a signed /bin/ls slice, a XAR, two digests.
max_len() {
    case $1 in
        macho | cdhash | symhash | unpack) echo 262144 ;;
        diff) echo 512 ;;
        *) echo 65536 ;;
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
                "$root"/Sources/fashion/*.swift "$root"/Sources/fashion/Algorithms/*.swift "$root"/Sources/fashion/Bridges/*.swift "$root"/Sources/fashion/Commands/*.swift -o "$out/fashion.o"
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
    rm -rf "${build:?}/fixtures" "${corpus:?}"
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
                for harness in macho cdhash symhash unpack; do
                    cp "$file" "$corpus/$harness/"
                done
                ;;
            78617221)
                cp "$file" "$corpus/xar/"
                ;;
        esac
        cp "$file" "$corpus/bytehash/"
    done

    # Digests to compare, from the fashion the tests built: each against the other, and against itself.
    local fashion digests first second algorithm
    fashion=$(xcrun swift build --package-path "$root" --scratch-path "$swiftpm" --show-bin-path)/fashion
    for algorithm in tlsh ssdeep; do
        digests=$("$fashion" -q -a "$algorithm" /bin/ls "$root/Sources/fashion/MachO.swift")
        first=$(echo "$digests" | sed -n 1p)
        second=$(echo "$digests" | sed -n 2p)
        printf '%s\0%s' "$first" "$second" > "$corpus/diff/$algorithm-pair"
        printf '%s' "$first" > "$corpus/diff/$algorithm-same"
    done

    for harness in $harnesses; do
        echo "$corpus/$harness: $(ls "$corpus/$harness" | wc -l | tr -d ' ') files"
    done
}

run() {
    local seconds=${1:-900} name harness dict
    if [ ! -d "$corpus" ]; then
        seed
    fi
    echo "Running every harness for $seconds seconds with $jobs workers each..."
    for name in $(binaries); do
        harness=${name#fuzz-}
        harness=${harness%-segments}
        dict=()
        if [ -f "$root/Fuzz/$harness.dict" ]; then
            dict=(-dict="$root/Fuzz/$harness.dict")
        fi
        rm -rf "${logs:?}/${name:?}"
        mkdir -p "$artifacts/$name" "$logs/$name"
        (cd "$logs/$name" && "$bin/$name" -jobs="$jobs" -workers="$jobs" -max_total_time="$seconds" -timeout=10 \
            -rss_limit_mb=2048 -malloc_limit_mb=512 -use_value_profile=1 -print_final_stats=1 \
            -max_len="$(max_len "$harness")" ${dict[@]+"${dict[@]}"} -artifact_prefix="$artifacts/$name/" \
            "$corpus/$harness" > "$name.log" 2>&1) &
    done
    wait
    summary
}

# Each worker's log (fuzz-<n>.log, next to the parent's) ends with its final stats: the runs and executions per second
# are summed over the workers, the coverage is the most edges any of them reached.
summary() {
    local name runs rate cov found
    for name in $(binaries); do
        [ -d "$logs/$name" ] || continue
        runs=$(cat "$logs/$name"/fuzz-[0-9]*.log 2>/dev/null | awk '/stat::number_of_executed_units/ { sum += $2 } END { print sum + 0 }')
        rate=$(cat "$logs/$name"/fuzz-[0-9]*.log 2>/dev/null | awk '/stat::average_exec_per_sec/ { sum += $2 } END { print sum + 0 }')
        cov=$(cat "$logs/$name"/fuzz-[0-9]*.log 2>/dev/null | grep -o 'cov: [0-9]*' | awk '{ if ($2 > max) max = $2 } END { print max + 0 }' || true)
        found=$(ls "$artifacts/$name" 2>/dev/null | wc -l | tr -d ' ')
        printf '%-24s %12s runs %8s exec/s  cov %-6s artifacts %s\n' "$name" "$runs" "$rate" "$cov" "$found"
        ls "$artifacts/$name" 2>/dev/null | sed 's/^/    /'
    done
}

case ${1:-} in
    build | seed | run | summary)
        "$@"
        ;;
    *)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
