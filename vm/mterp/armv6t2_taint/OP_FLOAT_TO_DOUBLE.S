%verify "executed"
%include "armv6t2_taint/unopWider.S" {"instr":"bl      __aeabi_f2d"}
