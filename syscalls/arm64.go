//go:build arm64

package syscalls

import "syscall"

// https://man7.org/linux/man-pages/man2/syscall.2.html
//   Arch/ABI    arg1  arg2  arg3  arg4  arg5  arg6  arg7   Notes
//   ────────────────────────────────────────────────────────────
//   arm64       x0    x1    x2    x3    x4    x5    -
//
//   Arch/ABI    Instruction       System  Ret  Ret  Error  Notes
//                                 call #  val  val2
//   ────────────────────────────────────────────────────────────
//   arm64       svc #0            w8      x0   x1   -

func init() {
	MapRegs = func(regs syscall.PtraceRegs) Regs {
		// type PtraceRegs struct {
		// 	Regs   [31]uint64
		// 	Sp     uint64
		// 	Pc     uint64
		// 	Pstate uint64
		// }
		// Sp: stack pointer, Pc: program counter, x: 64 bits, w: 32 bits
		return Regs{
			SyscallNum: int(regs.Regs[8]),
			Arg1:       int(regs.Regs[0]),
			Arg2:       int(regs.Regs[1]),
			Arg3:       int(regs.Regs[2]),
			Arg4:       int(regs.Regs[3]),
			Arg5:       int(regs.Regs[4]),
			Arg6:       int(regs.Regs[5]),
			RetVal:     int(regs.Regs[0]),
		}
	}
}
