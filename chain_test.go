package bpfutils

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

func TestChainTypeString(t *testing.T) {
	cases := []struct {
		input  ChainType
		output string
	}{
		{
			input:  0,
			output: "undefined",
		},
		{
			input:  1,
			output: "and",
		},
		{
			input:  2,
			output: "or",
		},
		{
			input:  3,
			output: "undefined",
		},
	}

	for _, test := range cases {
		if test.input.String() != test.output {
			t.Errorf("got: %s, expected: %s", test.input.String(), test.output)
		}
	}
}

func TestChainFilter(t *testing.T) {
	cases := []struct {
		description string
		inputA      []bpf.Instruction
		inputB      []bpf.Instruction
		expectAnd   []bpf.Instruction
		expectOr    []bpf.Instruction
	}{
		{
			description: "combine two filters both with RetConstant",
			inputA: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			inputB: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			expectAnd: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.Jump{Skip: 1},
				bpf.RetConstant{Val: 0},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			expectOr: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			description: "combine two filters one with RetConstant and the other with RetA",
			inputA: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			inputB: []bpf.Instruction{
				bpf.TAX{},
				bpf.RetA{},
			},
			expectAnd: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.Jump{Skip: 1},
				bpf.RetConstant{Val: 0},
				bpf.TAX{},
				bpf.RetA{},
			},
			expectOr: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.TAX{},
				bpf.RetA{},
			},
		},
		{
			description: "combine two filters one with RetA and the other with RetConstant",
			inputA: []bpf.Instruction{
				bpf.TAX{},
				bpf.RetA{},
			},
			inputB: []bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			expectAnd: []bpf.Instruction{
				bpf.TAX{},
				bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetA{},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
			expectOr: []bpf.Instruction{
				bpf.TAX{},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetA{},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetConstant{Val: 1},
				bpf.RetConstant{Val: 0},
			},
		},
		{
			description: "combine two filters both with RetA",
			inputA: []bpf.Instruction{
				bpf.TAX{},
				bpf.RetA{},
			},
			inputB: []bpf.Instruction{
				bpf.TAX{},
				bpf.RetA{},
			},
			expectAnd: []bpf.Instruction{
				bpf.TAX{},
				bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetA{},
				bpf.TAX{},
				bpf.RetA{},
			},
			expectOr: []bpf.Instruction{
				bpf.TAX{},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1, SkipFalse: 0},
				bpf.RetA{},
				bpf.TAX{},
				bpf.RetA{},
			},
		},
	}

	handle, err := pcap.OpenOffline("pcap/test_loopback.pcap")
	if err != nil {
		t.Fatalf("failed to open pcap handle: %s", err.Error())
	}
	defer handle.Close()

	for _, test := range cases {
		gotAnd := ChainFilter(test.inputA, test.inputB, AND)

		if !reflect.DeepEqual(gotAnd, test.expectAnd) {
			t.Errorf("case '%s'\nprogram not correctly combined with AND\n\ngot:\n%s\n\n, expected:\n%s\n", test.description, AsmString(gotAnd), AsmString(test.expectAnd))
		}

		gotAndRaw, err := bpf.Assemble(gotAnd)
		if err != nil {
			t.Errorf("case '%s': failed to assemble with error: %s\n%s", test.description, err.Error(), AsmString(gotAnd))
		}
		err = handle.SetBPFInstructionFilter(ToPcapBPFInstructions(gotAndRaw))
		if err != nil {
			t.Errorf("case '%s': failed to set BPF instructions with error: %s\n%s", test.description, err.Error(), AsmString(gotAnd))
		}
		gopacket.NewPacketSource(handle, handle.LinkType())

		gotOr := ChainFilter(test.inputA, test.inputB, OR)

		if !reflect.DeepEqual(gotOr, test.expectOr) {
			t.Errorf("case '%s'\nprogram not correctly combined with OR\n\ngot:\n%s\n\n, expected:\n%s\n", test.description, AsmString(gotOr), AsmString(test.expectOr))
		}

		gotOrRaw, err := bpf.Assemble(gotOr)
		if err != nil {
			t.Errorf("case '%s': failed to assemble with error: %s\n%s", test.description, err.Error(), AsmString(gotOr))
		}
		err = handle.SetBPFInstructionFilter(ToPcapBPFInstructions(gotOrRaw))
		if err != nil {
			t.Errorf("case '%s': failed to set BPF instructions with error: %s\n%s", test.description, err.Error(), AsmString(gotOr))
		}

		// Same for ChainPcapFilter
		inputApcap, err := bpf.Assemble(test.inputA)
		if err != nil {
			t.Errorf("case '%s': failed to assemble input.A with error: %s\n%#v", test.description, err.Error(), test.inputA)
		}

		inputBpcap, err := bpf.Assemble(test.inputB)
		if err != nil {
			t.Errorf("case '%s': failed to assemble input.B with error: %s\n%#v", test.description, err.Error(), test.inputB)
		}

		gotAndPcap, err := ChainPcapFilter(ToPcapBPFInstructions(inputApcap), ToPcapBPFInstructions(inputBpcap), AND)
		if err != nil {
			t.Fatal(test.inputA, test.inputB, err)
		}

		err = handle.SetBPFInstructionFilter(gotAndPcap)
		if err != nil {
			t.Errorf("case '%s': failed to set BPF instructions with error: %s\n%#v", test.description, err.Error(), gotAndPcap)
		}

		gotOrPcap, err := ChainPcapFilter(ToPcapBPFInstructions(inputApcap), ToPcapBPFInstructions(inputBpcap), OR)
		if err != nil {
			t.Fatal(test.inputA, test.inputB, err)
		}

		err = handle.SetBPFInstructionFilter(gotOrPcap)
		if err != nil {
			t.Errorf("case '%s': failed to set BPF instructions with error: %s\n%#v", test.description, err.Error(), gotOrPcap)
		}

	}
}
