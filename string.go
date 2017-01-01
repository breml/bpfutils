package bpfutils

import (
	"bytes"
	"fmt"

	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

// String disassembles []pcap.BPFInstruction an return them in the Go representation of bpf.Instruction
func String(a []pcap.BPFInstruction) string {
	var buffer bytes.Buffer
	for _, bpfInst := range ToBpfRawInstructions(a) {
		_, err := buffer.WriteString(fmt.Sprintf("%#v\n", bpfInst.Disassemble()))
		if err != nil {
			// TODO: Should we change the function sig and return this err?
			return ""
		}
	}
	return buffer.String()
}

// AsmString returns []bpf.Instruction as bpf_asm instructions as defined in
// https://www.kernel.org/doc/Documentation/networking/filter.txt
func AsmString(a []bpf.Instruction) string {
	var buffer bytes.Buffer
	for _, bpfInst := range a {
		_, err := buffer.WriteString(asmString(bpfInst))
		if err != nil {
			// TODO: Should we change the function sig and return this err?
			return ""
		}
	}
	return buffer.String()
}

// TODO: Implement support for labels when printing the disassembled assembler code
func asmString(instr bpf.Instruction) string {
	switch inst := instr.(type) {
	case bpf.ALUOpConstant:
		switch inst.Op {
		case bpf.ALUOpAdd:
			return fmt.Sprintf("add #%d\n", inst.Val)
		case bpf.ALUOpSub:
			return fmt.Sprintf("sub #%d\n", inst.Val)
		case bpf.ALUOpMul:
			return fmt.Sprintf("mul #%d\n", inst.Val)
		case bpf.ALUOpDiv:
			return fmt.Sprintf("div #%d\n", inst.Val)
		case bpf.ALUOpMod:
			return fmt.Sprintf("mod #%d\n", inst.Val)
		case bpf.ALUOpAnd:
			return fmt.Sprintf("and #%d\n", inst.Val)
		case bpf.ALUOpOr:
			return fmt.Sprintf("or #%d\n", inst.Val)
		case bpf.ALUOpXor:
			return fmt.Sprintf("xor #%d\n", inst.Val)
		case bpf.ALUOpShiftLeft:
			return fmt.Sprintf("lsh #%d\n", inst.Val)
		case bpf.ALUOpShiftRight:
			return fmt.Sprintf("rsh #%d\n", inst.Val)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.ALUOpX:
		switch inst.Op {
		case bpf.ALUOpAdd:
			return "add x\n"
		case bpf.ALUOpSub:
			return "sub x\n"
		case bpf.ALUOpMul:
			return "mul x\n"
		case bpf.ALUOpDiv:
			return "div x\n"
		case bpf.ALUOpMod:
			return "mod x\n"
		case bpf.ALUOpAnd:
			return "and x\n"
		case bpf.ALUOpOr:
			return "or x\n"
		case bpf.ALUOpXor:
			return "xor x\n"
		case bpf.ALUOpShiftLeft:
			return "lsh x\n"
		case bpf.ALUOpShiftRight:
			return "rsh x\n"
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.Jump:
		return fmt.Sprintf("jmp %d\n", inst.Skip)

	case bpf.JumpIf:
		switch inst.Cond {
		// K == A
		case bpf.JumpEqual:
			return conditionalJump(inst, "jeq", "jneq")
		// K != A
		case bpf.JumpNotEqual:
			return fmt.Sprintf("jneq #%d,%d\n", inst.Val, inst.SkipTrue)
		// K > A
		case bpf.JumpGreaterThan:
			return conditionalJump(inst, "jgt", "jle")
		// K < A
		case bpf.JumpLessThan:
			return fmt.Sprintf("jlt #%d,%d\n", inst.Val, inst.SkipTrue)

		// K >= A
		case bpf.JumpGreaterOrEqual:
			return conditionalJump(inst, "jge", "jlt")
		// K <= A
		case bpf.JumpLessOrEqual:
			return fmt.Sprintf("jle #%d,%d\n", inst.Val, inst.SkipTrue)
		// K & A != 0
		case bpf.JumpBitsSet:
			if inst.SkipFalse > 0 {
				return fmt.Sprintf("jset #%d,%d,%d\n", inst.Val, inst.SkipTrue, inst.SkipFalse)
			}
			return fmt.Sprintf("jset #%d,%d\n", inst.Val, inst.SkipTrue)
		// K & A == 0
		//case bpf.JumpBitsNotSet:
		//	if inst.SkipFalse > 0 {
		//		return fmt.Sprintf("jnset #%d,%d,%d\n", inst.Val, inst.SkipTrue, inst.SkipFalse)
		//	} else {
		//		return fmt.Sprintf("jnset #%d,%d\n", inst.Val, inst.SkipTrue)
		//	}
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.LoadAbsolute:
		switch inst.Size {
		case 1: // byte
			return fmt.Sprintf("ldb [%d]\n", inst.Off)
		case 2: // half word
			return fmt.Sprintf("ldh [%d]\n", inst.Off)
		case 4: // word
			if inst.Off > 0xFFFFFFFF-0x1000 {
				return loadExtension(bpf.LoadExtension{Num: bpf.Extension(inst.Off + 0x1000)})
			}
			return fmt.Sprintf("ld [%d]\n", inst.Off)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.LoadConstant:
		switch inst.Dst {
		case bpf.RegA:
			return fmt.Sprintf("ld #%d\n", inst.Val)
		case bpf.RegX:
			return fmt.Sprintf("ldx #%d\n", inst.Val)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.LoadExtension:
		return loadExtension(inst)

	case bpf.LoadIndirect:
		switch inst.Size {
		case 1: // byte
			return fmt.Sprintf("ldb [x + %d]\n", inst.Off)
		case 2: // half word
			return fmt.Sprintf("ldh [x + %d]\n", inst.Off)
		case 4: // word
			return fmt.Sprintf("ld [x + %d]\n", inst.Off)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.LoadMemShift:
		return fmt.Sprintf("ldx 4*([%d]&0xf)\n", inst.Off)

	case bpf.LoadScratch:
		switch inst.Dst {
		case bpf.RegA:
			return fmt.Sprintf("ld M[%d]\n", inst.N)
		case bpf.RegX:
			return fmt.Sprintf("ldx M[%d]\n", inst.N)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.NegateA:
		return "neg\n"

	case bpf.RetA:
		return "ret a\n"

	case bpf.RetConstant:
		return fmt.Sprintf("ret #%d\n", inst.Val)

	case bpf.StoreScratch:
		switch inst.Src {
		case bpf.RegA:
			return fmt.Sprintf("st M[%d]\n", inst.N)
		case bpf.RegX:
			return fmt.Sprintf("stx M[%d]\n", inst.N)
		default:
			return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
		}

	case bpf.TAX:
		return "tax\n"

	case bpf.TXA:
		return "txa\n"

	default:
		return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
	}
}

func conditionalJump(inst bpf.JumpIf, positiveJump, negativeJump string) string {
	if inst.SkipTrue > 0 {
		if inst.SkipFalse > 0 {
			return fmt.Sprintf("%s #%d,%d,%d\n", positiveJump, inst.Val, inst.SkipTrue, inst.SkipFalse)
		}
		return fmt.Sprintf("%s #%d,%d\n", positiveJump, inst.Val, inst.SkipTrue)
	}
	return fmt.Sprintf("%s #%d,%d\n", negativeJump, inst.Val, inst.SkipFalse)
}

func loadExtension(inst bpf.LoadExtension) string {
	switch inst.Num {
	case bpf.ExtLen:
		return "ld #len\n"
	case bpf.ExtProto:
		return "ld #proto\n"
	case bpf.ExtType:
		return "ld #type\n"
	case bpf.ExtRand:
		return "ld #rand\n"
	default:
		return fmt.Sprintf("!! unknown instruction: %#v\n", inst)
	}
}
