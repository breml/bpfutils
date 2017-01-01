package bpfutils

import (
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

func TestAsmString(t *testing.T) {
	cases := []struct {
		input  bpf.Instruction
		expect string
	}{
		{
			input:  bpf.LoadConstant{Dst: bpf.RegA, Val: 42},
			expect: "ld #42",
		},
		{
			input:  bpf.LoadConstant{Dst: bpf.RegX, Val: 42},
			expect: "ldx #42",
		},
		{
			input:  bpf.LoadScratch{Dst: bpf.RegA, N: 3},
			expect: "ld M[3]",
		},
		{
			input:  bpf.LoadScratch{Dst: bpf.RegX, N: 3},
			expect: "ldx M[3]",
		},
		{
			input:  bpf.LoadAbsolute{Off: 42, Size: 1},
			expect: "ldb [42]",
		},
		{
			input:  bpf.LoadAbsolute{Off: 42, Size: 2},
			expect: "ldh [42]",
		},
		{
			input:  bpf.LoadAbsolute{Off: 42, Size: 4},
			expect: "ld [42]",
		},
		{
			input:  bpf.LoadIndirect{Off: 42, Size: 1},
			expect: "ldb [x + 42]",
		},
		{
			input:  bpf.LoadIndirect{Off: 42, Size: 2},
			expect: "ldh [x + 42]",
		},
		{
			input:  bpf.LoadIndirect{Off: 42, Size: 4},
			expect: "ld [x + 42]",
		},
		{
			input:  bpf.LoadMemShift{Off: 42},
			expect: "ldx 4*([42]&0xf)",
		},
		{
			input:  bpf.LoadExtension{Num: bpf.ExtLen},
			expect: "ld #len",
		},
		{
			input:  bpf.LoadExtension{Num: bpf.ExtProto},
			expect: "ld #proto",
		},
		{
			input:  bpf.LoadExtension{Num: bpf.ExtType},
			expect: "ld #type",
		},
		{
			input:  bpf.LoadExtension{Num: bpf.ExtRand},
			expect: "ld #rand",
		},
		{
			input:  bpf.StoreScratch{Src: bpf.RegA, N: 3},
			expect: "st M[3]",
		},
		{
			input:  bpf.StoreScratch{Src: bpf.RegX, N: 3},
			expect: "stx M[3]",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 42},
			expect: "add #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpSub, Val: 42},
			expect: "sub #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpMul, Val: 42},
			expect: "mul #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpDiv, Val: 42},
			expect: "div #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpOr, Val: 42},
			expect: "or #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: 42},
			expect: "lsh #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 42},
			expect: "rsh #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpMod, Val: 42},
			expect: "mod #42",
		},
		{
			input:  bpf.ALUOpConstant{Op: bpf.ALUOpXor, Val: 42},
			expect: "xor #42",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpAdd},
			expect: "add x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpSub},
			expect: "sub x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpMul},
			expect: "mul x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpDiv},
			expect: "div x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpOr},
			expect: "or x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpShiftLeft},
			expect: "lsh x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpShiftRight},
			expect: "rsh x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpMod},
			expect: "mod x",
		},
		{
			input:  bpf.ALUOpX{Op: bpf.ALUOpXor},
			expect: "xor x",
		},
		{
			input:  bpf.NegateA{},
			expect: "neg",
		},
		{
			input:  bpf.Jump{Skip: 10},
			expect: "jmp 10",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpEqual, Val: 42, SkipTrue: 8, SkipFalse: 9},
			expect: "jeq #42,8,9",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 42, SkipTrue: 8},
			expect: "jneq #42,8",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 42, SkipTrue: 7},
			expect: "jlt #42,7",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: 42, SkipTrue: 6},
			expect: "jle #42,6",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 42, SkipTrue: 4, SkipFalse: 5},
			expect: "jgt #42,4,5",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: 42, SkipTrue: 3, SkipFalse: 4},
			expect: "jge #42,3,4",
		},
		{
			input:  bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 42, SkipTrue: 2, SkipFalse: 3},
			expect: "jset #42,2,3",
		},
		{
			input:  bpf.TAX{},
			expect: "tax",
		},
		{
			input:  bpf.TXA{},
			expect: "txa",
		},
		{
			input:  bpf.RetA{},
			expect: "ret a",
		},
		{
			input:  bpf.RetConstant{Val: 42},
			expect: "ret #42",
		},
	}

	for _, test := range cases {
		got := strings.TrimRight(AsmString([]bpf.Instruction{test.input}), "\n")
		if got != test.expect {
			t.Errorf("AsmString failed, got: %s, expected: %s", got, test.expect)
		}
	}
}
