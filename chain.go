package bpfutils

import (
	"fmt"

	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

// Possible ChainType values
const (
	UNDEFINED = iota
	AND
	OR
)

// ChainType defines possible chain operations for BPF filters.
// Currently only AND and OR are supported. For details see documentation of function ChainFilter.
type ChainType int

// String returns a string representation of ChainType.
func (c ChainType) String() string {
	switch c {
	case AND:
		return "and"
	case OR:
		return "or"
	case UNDEFINED:
		return "undefined"
	default:
		return "undefined"
	}
}

// ChainFilter combines two BPF filters to a single BPF filter by rewriting the `ret #k` and `ret a`
// instructions.
//
// For `ret #k`, in the first BPF block `ret #k` is replaced with `jmp`, if the second block has to
// be evaluated as well:
// * AND-case: only evaluate second block,
//   if a packet would be returned after the first block (ret constant > 0)
// * OR-case: only evaluate second block,
//   if the packet would not be returned after the first block (ret constant == 0)
//
// For `ret a`, in the first BPF block `ret a` is replaced with a conditional Jump (jeq/jneq),
// if the second block has to be evaluated as well:
// * AND-case: only evaluate second block,
//   if a packet would be returned after the first block (register a > 0)
// * OR-case: only evaluate second block,
//   if the packet would not be returned after the first block (register a == 0)
func ChainFilter(a, b []bpf.Instruction, ct ChainType) ([]bpf.Instruction, error) {
	bpfChained := make([]bpf.Instruction, 0, len(a)+len(b)+10)
	offset := len(a)

	// Traverse BPF block A
	for i, instr := range a {
		switch inst := instr.(type) {
		case bpf.RetConstant:
			if (ct == AND && inst.Val > 0) || (ct == OR && inst.Val == 0) {
				// insert a jump, only if the skip value is more than 0
				if offset-i-1 > 0 {
					bpfChained = append(bpfChained, bpf.Jump{
						Skip: uint32(offset - i - 1),
					})
				}
				continue
			}
		case bpf.RetA:
			switch ct {
			case AND:
				bpfChained = append(bpfChained, bpf.JumpIf{
					Cond:     bpf.JumpNotEqual,
					Val:      0,
					SkipTrue: 1,
				}, instr)
			case OR:
				bpfChained = append(bpfChained, bpf.JumpIf{
					Cond:     bpf.JumpEqual,
					Val:      0,
					SkipTrue: 1,
				}, instr)
			}
			continue
		}
		bpfChained = append(bpfChained, instr)
	}

	// Add BPF block B
	bpfChained = append(bpfChained, b...)

	return bpfChained, nil
}

// ChainPcapFilter combines two []pcap.BPFInstruction BPF filter.
// Details see function ChainFilter
func ChainPcapFilter(a, b []pcap.BPFInstruction, ct ChainType) ([]pcap.BPFInstruction, error) {
	a0, ok := ToBpfInstructions(a)
	if !ok {
		return nil, fmt.Errorf("Unable to convert '%#v'", a)
	}
	b0, ok := ToBpfInstructions(b)
	if !ok {
		return nil, fmt.Errorf("Unable to convert '%#v'", b)
	}
	chainedBpf, err := ChainFilter(a0, b0, ct)
	if err != nil {
		return nil, err
	}
	rawBpf, err := bpf.Assemble(chainedBpf)
	if err != nil {
		return nil, err
	}
	return ToPcapBPFInstructions(rawBpf), nil
}
