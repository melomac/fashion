/*
 C helpers the Swift code needs:
 - Mach-O CPU subtypes missing from older SDKs. macOS 27 (Xcode 27) added CPU_SUBTYPE_ARM64E_X1 to <mach/machine.h>.
   This header supplies the same definition when building against an earlier SDK, so Swift code can use the SDK name
   unconditionally. It is guarded, so the SDK's own definition wins whenever it exists, and CMachOCompat.c then checks
   the fallback against it.
 - The fts(3) comparator of `--sort`, written in C so it reads FTSENT through whichever layout <fts.h> declares.
 */

#ifndef CMACHO_COMPAT_H
#define CMACHO_COMPAT_H

#include <fts.h>
#include <mach/machine.h>

#ifndef CPU_SUBTYPE_ARM64E_X1
#define CPU_SUBTYPE_ARM64E_X1 ((cpu_subtype_t) 12)
#endif

/*
 Order one directory's entries by the bytes of their names, a directory's name followed by "/", so that walking
 depth-first lists files in the byte order of their full paths ("a-b" and "a.txt" before "a/x", as '-' and '.' < '/').
 */
int fashion_fts_compare(const FTSENT **lhs, const FTSENT **rhs);

#endif /* CMACHO_COMPAT_H */
