%verify "executed"
%include "armv6t2_taint/unopNarrower.S" {"instr":"bl      __aeabi_l2f"}
