/*
 Mach-O CPU subtypes missing from older SDKs.

 macOS 27 (Xcode 27) added CPU_SUBTYPE_ARM64E_X1 to <mach/machine.h>. This header supplies the same definition
 when building against an earlier SDK, so Swift code can use the SDK name unconditionally. It is guarded, so the
 SDK's own definition wins whenever it exists, and CMachOCompat.c then checks the fallback against it.
 */

#ifndef CMACHO_COMPAT_H
#define CMACHO_COMPAT_H

#include <mach/machine.h>

#ifndef CPU_SUBTYPE_ARM64E_X1
#define CPU_SUBTYPE_ARM64E_X1 ((cpu_subtype_t) 12)
#endif

#endif /* CMACHO_COMPAT_H */
