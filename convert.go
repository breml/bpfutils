package bpfutils

import (
	"unsafe"

	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

// ToPcapBPFInstructions converts a []bpf.RawInstruction into a []pcap.BPFInstruction
//#nosec
func ToPcapBPFInstructions(in []bpf.RawInstruction) []pcap.BPFInstruction {
	return *(*[]pcap.BPFInstruction)(unsafe.Pointer(&in))
}

// ToPcapBPFInstruction converts a bpf.RawInstruction into a pcap.BPFInstruction
//#nosec
func ToPcapBPFInstruction(in bpf.RawInstruction) pcap.BPFInstruction {
	return *(*pcap.BPFInstruction)(unsafe.Pointer(&in))
}

// ToBpfRawInstructions converts a []pcap.BPFInstruction into a []bpf.RawInstruction
//#nosec
func ToBpfRawInstructions(in []pcap.BPFInstruction) []bpf.RawInstruction {
	return *(*[]bpf.RawInstruction)(unsafe.Pointer(&in))
}

// ToBpfRawInstruction converts a pcap.BPFInstruction into a bpf.RawInstruction
//#nosec
func ToBpfRawInstruction(in pcap.BPFInstruction) bpf.RawInstruction {
	return *(*bpf.RawInstruction)(unsafe.Pointer(&in))
}

// ToBpfInstructions converts a []pcap.BPFInstruction into a []bpf.Instructions
func ToBpfInstructions(in []pcap.BPFInstruction) ([]bpf.Instruction, bool) {
	return bpf.Disassemble(ToBpfRawInstructions(in))
}

// ToBpfInstruction converts a pcap.BPFInstruction into a bpf.Instruction
func ToBpfInstruction(in pcap.BPFInstruction) bpf.Instruction {
	return ToBpfRawInstruction(in).Disassemble()
}
