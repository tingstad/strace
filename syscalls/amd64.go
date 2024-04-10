//go:build amd64

package syscalls

import "syscall"

// https://man7.org/linux/man-pages/man2/syscall.2.html
//   Arch/ABI    arg1  arg2  arg3  arg4  arg5  arg6  arg7   Notes
//   ────────────────────────────────────────────────────────────
//   x86-64      rdi   rsi   rdx   r10   r8    r9    -
//
//   Arch/ABI    Instruction       System  Ret  Ret  Error  Notes
//                                 call #  val  val2
//   ────────────────────────────────────────────────────────────
//   x86-64      syscall           rax     rax  rdx  -      5

func init() {
	MapRegs = func(regs syscall.PtraceRegs) Regs {
		return Regs{
			SyscallNum: int(regs.Orig_rax),
			Arg1:       int(regs.Rdi),
			Arg2:       int(regs.Rsi),
			Arg3:       int(regs.Rdx),
			Arg4:       int(regs.R10),
			Arg5:       int(regs.R8),
			Arg6:       int(regs.R9),
			RetVal:     int(regs.Rax),
		}
	}
}
