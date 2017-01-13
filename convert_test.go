package bpfutils

import (
	"reflect"
	"testing"

	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

func TestToPcapBPFInstruction(t *testing.T) {
	cases := []struct {
		raw  []bpf.RawInstruction
		pcap []pcap.BPFInstruction
		bpf  []bpf.Instruction
	}{
		{
			/*
			   # get a random uint32 number
			   ld rand
			   # if rand is greater than 4294967 (maxuint32 / 1000), drop the package
			   jgt #4294967, drop
			   capture:
			   # ret > 0 -> capture number of byte of the packets
			   ret #1024
			   drop:
			   # ret = 0 -> do not capture the packet
			   ret #0
			*/
			raw: []bpf.RawInstruction{
				{Op: 0x20, Jt: 0, Jf: 0, K: 0xfffff038},
				{Op: 0x25, Jt: 1, Jf: 0, K: 4294967},
				{Op: 0x06, Jt: 0, Jf: 0, K: 0x00000400},
				{Op: 0x06, Jt: 0, Jf: 0, K: 0000000000},
			},
			pcap: []pcap.BPFInstruction{
				{Code: 0x20, Jt: 0, Jf: 0, K: 0xfffff038},
				{Code: 0x25, Jt: 1, Jf: 0, K: 4294967},
				{Code: 0x06, Jt: 0, Jf: 0, K: 0x00000400},
				{Code: 0x06, Jt: 0, Jf: 0, K: 0000000000},
			},
			bpf: []bpf.Instruction{
				bpf.LoadExtension{Num: bpf.ExtRand},
				bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 4294967, SkipTrue: 1},
				bpf.RetConstant{Val: 1024},
				bpf.RetConstant{Val: 0},
			},
		},
	}

	for _, test := range cases {
		gotPcap := ToPcapBPFInstructions(test.raw)
		if !reflect.DeepEqual(test.pcap, gotPcap) {
			t.Errorf("ToPcapBPFInstructions failed, got: %#v, expected: %#v", gotPcap, test.pcap)
		}

		for i, inst := range test.raw {
			got := ToPcapBPFInstruction(inst)
			if !reflect.DeepEqual(test.pcap[i], got) {
				t.Errorf("ToPcapBPFInstruction failed, got: %#v, expected: %#v", got, test.pcap[i])
			}
		}

		gotRaw := ToBpfRawInstructions(test.pcap)
		if !reflect.DeepEqual(test.raw, gotRaw) {
			t.Errorf("ToBpfRawInstruction failed, got: %#v, expected: %#v", gotRaw, test.raw)
		}

		for i, inst := range test.pcap {
			got := ToBpfRawInstruction(inst)
			if !reflect.DeepEqual(test.raw[i], got) {
				t.Errorf("ToRawBPFInstruction failed, got: %#v, expected: %#v", got, test.raw[i])
			}
		}

		gotBpf, ok := ToBpfInstructions(test.pcap)
		if !ok || !reflect.DeepEqual(test.bpf, gotBpf) {
			t.Errorf("ToBpfInstruction failed, got: %#v, expected: %#v", gotBpf, test.bpf)
		}

		for i, inst := range test.pcap {
			got := ToBpfInstruction(inst)
			if !reflect.DeepEqual(test.bpf[i], got) {
				t.Errorf("ToBPFInstruction failed, got: %#v, expected: %#v", got, test.bpf[i])
			}
		}

	}
}
