/*
 C helpers the Swift code needs:
 - Mach-O constants missing from older SDKs. macOS 27 (Xcode 27) added CPU_SUBTYPE_ARM64E_X1 to <mach/machine.h>, and
   macOS 26 the load commands below to <mach-o/loader.h>. This header supplies the same definitions when building
   against an earlier SDK, so Swift code can use the SDK names unconditionally. They are guarded, so the SDK's own
   definition wins whenever it exists, and CMachOCompat.c then checks each fallback against it.
 - The fts(3) comparator of `--sort`, written in C so it reads FTSENT through whichever layout <fts.h> declares.
 */

#ifndef CMACHO_COMPAT_H
#define CMACHO_COMPAT_H

#include <fts.h>
#include <mach-o/loader.h>
#include <mach/machine.h>

#ifndef CPU_SUBTYPE_ARM64E_X1
#define CPU_SUBTYPE_ARM64E_X1 ((cpu_subtype_t) 12)
#endif

#ifndef LC_FUNCTION_VARIANTS
#define LC_FUNCTION_VARIANTS 0x37
#endif
#ifndef LC_FUNCTION_VARIANT_FIXUPS
#define LC_FUNCTION_VARIANT_FIXUPS 0x38
#endif
#ifndef LC_TARGET_TRIPLE
#define LC_TARGET_TRIPLE 0x39
#endif
#ifndef LC_LAZY_LOAD_DYLIB_INFO
#define LC_LAZY_LOAD_DYLIB_INFO 0x3A
#endif

/*
 Order one directory's entries, or the roots of a walk, by the bytes of their names, a directory's name followed by
 "/", so that walking depth-first lists files in the byte order of their full paths ("a-b" and "a.txt" before "a/x", as
 '-' and '.' < '/'). A root's name is its whole path: "dir" sorts before "dir/sub".
 */
int fashion_fts_compare(const FTSENT **lhs, const FTSENT **rhs);

#endif /* CMACHO_COMPAT_H */
