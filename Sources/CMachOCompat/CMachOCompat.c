/*
 SwiftPM needs one translation unit per target. This one also verifies the fallback in CMachOCompat.h: on an SDK
 that defines the subtype itself the guarded fallback is inert, and the assertion compares the SDK's value with
 the one the fallback would have supplied.
 */
#include "CMachOCompat.h"

_Static_assert(CPU_SUBTYPE_ARM64E_X1 == 12, "CMachOCompat.h fallback for CPU_SUBTYPE_ARM64E_X1 disagrees with the SDK");
