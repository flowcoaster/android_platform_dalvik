/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Dalvik interpreter definitions.  These are internal to the interpreter.
 *
 * This includes defines, types, function declarations, and inline functions
 * that are common to all interpreter implementations.
 *
 * Functions and globals declared here are defined in Interp.c.
 */
#ifndef DALVIK_INTERP_STATE_H_
#define DALVIK_INTERP_STATE_H_

#ifdef WITH_TAINT_TRACKING
#include "interp/Taint.h"
#endif

/*
 * For x86 JIT. In the lowered code sequences for bytecodes, at most 10
 * temporary variables may be live at the same time. Therefore, at most
 * 10 temporary variables can be spilled at the same time.
*/
#define MAX_SPILL_JIT_IA 10

/*
 * Execution mode, e.g. interpreter vs. JIT.
 */
enum ExecutionMode {
    kExecutionModeUnknown = 0,
    kExecutionModeInterpPortable,
    kExecutionModeInterpFast,
#if defined(WITH_JIT)
    kExecutionModeJit,
#endif
#if defined(WITH_JIT)  /* IA only */
    kExecutionModeNcgO0,
    kExecutionModeNcgO1,
#endif
};

/*
 * Execution sub modes, e.g. debugging, profiling, etc.
 * Treated as bit flags for fast access.  These values are used directly
 * by assembly code in the mterp interpeter and may also be used by
 * code generated by the JIT.  Take care when changing.
 */
enum ExecutionSubModes {
    kSubModeNormal            = 0x0000,   /* No active subMode */
    kSubModeMethodTrace       = 0x0001,
    kSubModeEmulatorTrace     = 0x0002,
    kSubModeInstCounting      = 0x0004,
    kSubModeDebuggerActive    = 0x0008,
    kSubModeSuspendPending    = 0x0010,
    kSubModeCallbackPending   = 0x0020,
    kSubModeCountedStep       = 0x0040,
    kSubModeCheckAlways       = 0x0080,
    kSubModeJitTraceBuild     = 0x4000,
    kSubModeJitSV             = 0x8000,
    kSubModeDebugProfile   = (kSubModeMethodTrace |
                              kSubModeEmulatorTrace |
                              kSubModeInstCounting |
                              kSubModeDebuggerActive)
};

/*
 * Interpreter break flags.  When set, causes the interpreter to
 * break from normal execution and invoke the associated callback
 * handler.
 */

enum InterpBreakFlags {
    kInterpNoBreak            = 0x00,    /* Don't check */
    kInterpSingleStep         = 0x01,    /* Check between each inst */
    kInterpSafePoint          = 0x02,    /* Check at safe points */
};

/*
 * Mapping between subModes and required check intervals.  Note: in
 * the future we might want to make this mapping target-dependent.
 */
#define SINGLESTEP_BREAK_MASK ( kSubModeInstCounting | \
                                kSubModeDebuggerActive | \
                                kSubModeCountedStep | \
                                kSubModeCheckAlways | \
                                kSubModeJitSV | \
                                kSubModeJitTraceBuild )

#define SAFEPOINT_BREAK_MASK  ( kSubModeSuspendPending | \
                                kSubModeCallbackPending )

typedef bool (*SafePointCallback)(struct Thread* thread, void* arg);

/*
 * Identify which break and submode flags should be local
 * to an interpreter activation.
 */
#define LOCAL_SUBMODE (kSubModeJitTraceBuild)

struct InterpSaveState {
    const u2*       pc;         // Dalvik PC
    u4*             curFrame;   // Dalvik frame pointer
    const Method    *method;    // Method being executed
    DvmDex*         methodClassDex;
    JValue          retval;
#ifdef WITH_TAINT_TRACKING
    Taint       rtaint;			// return taint value
#endif /* WITH_TAINT_TRACKING */
    void*           bailPtr;
#if defined(WITH_TRACKREF_CHECKS)
    int             debugTrackedRefStart;
#else
    int             unused;        // Keep struct size constant
#endif
    struct InterpSaveState* prev;  // To follow nested activations
} __attribute__ ((__packed__));

#ifdef WITH_JIT
/*
 * NOTE: Only entry points dispatched via [self + #offset] are put
 * in this struct, and there are six of them:
 * 1) dvmJitToInterpNormal: find if there is a corresponding compilation for
 *    the new dalvik PC. If so, chain the originating compilation with the
 *    target then jump to it. If the destination trace doesn't exist, update
 *    the profile count for that Dalvik PC.
 * 2) dvmJitToInterpNoChain: similar to dvmJitToInterpNormal but chaining is
 *    not performed.
 * 3) dvmJitToInterpPunt: use the fast interpreter to execute the next
 *    instruction(s) and stay there as long as it is appropriate to return
 *    to the compiled land. This is used when the jit'ed code is about to
 *    throw an exception.
 * 4) dvmJitToInterpSingleStep: use the portable interpreter to execute the
 *    next instruction only and return to pre-specified location in the
 *    compiled code to resume execution. This is mainly used as debugging
 *    feature to bypass problematic opcode implementations without
 *    disturbing the trace formation.
 * 5) dvmJitToTraceSelect: Similar to dvmJitToInterpNormal except for the
 *    profiling operation. If the new Dalvik PC is dominated by an already
 *    translated trace, directly request a new translation if the destinaion
 *    trace doesn't exist.
 * 6) dvmJitToBackwardBranch: special case for SELF_VERIFICATION when the
 *    destination Dalvik PC is included by the trace itself.
 */
struct JitToInterpEntries {
    void (*dvmJitToInterpNormal)(void);
    void (*dvmJitToInterpNoChain)(void);
    void (*dvmJitToInterpPunt)(void);
    void (*dvmJitToInterpSingleStep)(void);
    void (*dvmJitToInterpTraceSelect)(void);
#if defined(WITH_SELF_VERIFICATION)
    void (*dvmJitToInterpBackwardBranch)(void);
#else
    void (*unused)(void);  // Keep structure size constant
#endif
};

/* States of the interpreter when serving a JIT-related request */
enum JitState {
    /* Entering states in the debug interpreter */
    kJitNot = 0,               // Non-JIT related reasons */
    kJitTSelectRequest = 1,    // Request a trace (subject to filtering)
    kJitTSelectRequestHot = 2, // Request a hot trace (bypass the filter)
    kJitSelfVerification = 3,  // Self Verification Mode

    /* Operational states in the debug interpreter */
    kJitTSelect = 4,           // Actively selecting a trace
    kJitTSelectEnd = 5,        // Done with the trace - wrap it up
    kJitDone = 6,              // No further JIT actions for interpBreak
};

#if defined(WITH_SELF_VERIFICATION)
enum SelfVerificationState {
    kSVSIdle = 0,           // Idle
    kSVSStart = 1,          // Shadow space set up, running compiled code
    kSVSPunt = 2,           // Exiting compiled code by punting
    kSVSSingleStep = 3,     // Exiting compiled code by single stepping
    kSVSNoProfile = 4,      // Exiting compiled code and don't collect profiles
    kSVSTraceSelect = 5,    // Exiting compiled code and compile the next pc
    kSVSNormal = 6,         // Exiting compiled code normally
    kSVSNoChain = 7,        // Exiting compiled code by no chain
    kSVSBackwardBranch = 8, // Exiting compiled code with backward branch trace
    kSVSDebugInterp = 9,    // Normal state restored, running debug interpreter
};
#endif

/* Number of entries in the 2nd level JIT profiler filter cache */
#define JIT_TRACE_THRESH_FILTER_SIZE 32
/* Number of low dalvik pc address bits to include in 2nd level filter key */
#define JIT_TRACE_THRESH_FILTER_PC_BITS 4
#define MAX_JIT_RUN_LEN 64

enum JitHint {
   kJitHintNone = 0,
   kJitHintTaken = 1,         // Last inst in run was taken branch
   kJitHintNotTaken = 2,      // Last inst in run was not taken branch
   kJitHintNoBias = 3,        // Last inst in run was unbiased branch
};

/*
 * Element of a Jit trace description. If the isCode bit is set, it describes
 * a contiguous sequence of Dalvik byte codes.
 */
struct JitCodeDesc {
    unsigned numInsts:8;     // Number of Byte codes in run
    unsigned runEnd:1;       // Run ends with last byte code
    JitHint hint:7;          // Hint to apply to final code of run
    u2 startOffset;          // Starting offset for trace run
};

/*
 * A complete list of trace runs passed to the compiler looks like the
 * following:
 *   frag1
 *   frag2
 *   frag3
 *   meta1
 *     :
 *   metan
 *   frag4
 *
 * frags 1-4 have the "isCode" field set and describe the location/length of
 * real code traces, while metas 1-n are misc information.
 * The meaning of the meta content is loosely defined. It is usually the code
 * fragment right before the first meta field (frag3 in this case) to
 * understand and parse them. Frag4 could be a dummy one with 0 "numInsts" but
 * the "runEnd" field set.
 *
 * For example, if a trace run contains a method inlining target, the class
 * descriptor/loader of "this" and the currently resolved method pointer are
 * three instances of meta information stored there.
 */
struct JitTraceRun {
    union {
        JitCodeDesc frag;
        void*       meta;
    } info;
    u4 isCode:1;
    u4 unused:31;
};

#if defined(ARCH_IA32)
/*
 * JIT code genarator optimization level
 */
enum JitOptLevel {
    kJitOptLevelO0 = 0,
    kJitOptLevelO1 = 1,
};
#endif  // #if defined(ARCH_IA32)
#endif

#endif  // DALVIK_INTERP_STATE_H_
