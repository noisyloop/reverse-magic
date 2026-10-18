//go:build js && wasm

// Teardown disassembler. Compiles Go's x/arch decoders (BSD-3, see LICENSE-x-arch)
// to WebAssembly and exposes one function to JavaScript:
//
//	teardownDisasm(arch, bytes, baseAddr, maxInsns, syntax) -> [{addr, len, bytes, text, bad}]
//
// It only decodes bytes into text. It never executes or emulates anything.
package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall/js"

	"teardown/disasm/internal/arm64asm"
	"teardown/disasm/internal/armasm"
	"teardown/disasm/internal/ppc64asm"
	"teardown/disasm/internal/riscv64asm"
	"teardown/disasm/internal/x86asm"
)

type insn struct {
	n       int
	text    string
	bad     bool
	partial bool // length is right but the mnemonic is not decoded
}

func isLegacyPrefix(b byte) bool {
	switch b {
	case 0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65:
		return true
	}
	return false
}

// x86Special covers encodings Go's x86asm does not know: CET's endbr32/endbr64
// (every function starts with one in modern distro builds) and VEX/EVEX (AVX,
// AVX2, AVX-512). For VEX/EVEX it only works out the instruction length so the
// sweep stays in sync; the mnemonic is reported as undecoded rather than guessed.
func x86Special(src []byte, mode int) (insn, bool) {
	if len(src) >= 4 && src[0] == 0xf3 && src[1] == 0x0f && src[2] == 0x1e && (src[3] == 0xfa || src[3] == 0xfb) {
		if src[3] == 0xfa {
			return insn{n: 4, text: "endbr64"}, true
		}
		return insn{n: 4, text: "endbr32"}, true
	}
	i := 0
	for i < len(src) && i < 4 && isLegacyPrefix(src[i]) {
		i++
	}
	if i >= len(src) {
		return insn{}, false
	}
	b := src[i]
	if b != 0xc4 && b != 0xc5 && b != 0x62 {
		return insn{}, false
	}
	// Outside 64-bit mode these bytes are LES/LDS/BOUND unless the next byte has mod=11.
	if mode != 64 && (i+1 >= len(src) || src[i+1]&0xc0 != 0xc0) {
		return insn{}, false
	}
	var pos, opmap int
	switch b {
	case 0xc5:
		pos, opmap = i+2, 1
	case 0xc4:
		if i+3 > len(src) {
			return insn{}, false
		}
		pos, opmap = i+3, int(src[i+1]&0x1f)
	default: // 0x62 EVEX: 4-byte prefix
		if i+4 > len(src) {
			return insn{}, false
		}
		pos, opmap = i+4, int(src[i+1]&0x07)
	}
	if pos+2 > len(src) {
		return insn{}, false
	}
	opcode := src[pos]
	pos++
	if b != 0x62 && opmap == 1 && opcode == 0x77 { // vzeroupper / vzeroall: no ModRM
		name := "vzeroupper"
		if b == 0xc4 && src[i+2]&0x04 != 0 || b == 0xc5 && src[i+1]&0x04 != 0 {
			name = "vzeroall"
		}
		return insn{n: pos, text: name}, true
	}
	modrm := src[pos]
	pos++
	mod, rm := modrm>>6, modrm&7
	if mod != 3 && rm == 4 {
		if pos >= len(src) {
			return insn{}, false
		}
		sib := src[pos]
		pos++
		if mod == 0 && sib&7 == 5 {
			pos += 4
		}
	}
	switch {
	case mod == 0 && rm == 5:
		pos += 4
	case mod == 1:
		pos++
	case mod == 2:
		pos += 4
	}
	if opmap == 3 || (opmap == 1 && (opcode >= 0x70 && opcode <= 0x73 || opcode == 0xc2 || opcode >= 0xc4 && opcode <= 0xc6)) {
		pos++
	}
	if pos > len(src) {
		return insn{}, false
	}
	kind := "vex"
	if b == 0x62 {
		kind = "evex"
	}
	return insn{n: pos, text: fmt.Sprintf("(%s map%d op %02x, mnemonic not decoded)", kind, opmap, opcode), partial: true}, true
}

// decodeOne decodes a single instruction at the start of src.
func decodeOne(arch string, src []byte, pc uint64, syntax string) insn {
	switch arch {
	case "x86-32", "x86-64":
		mode := 64
		if arch == "x86-32" {
			mode = 32
		}
		if sp, ok := x86Special(src, mode); ok {
			return sp
		}
		inst, err := x86asm.Decode(src, mode)
		if err != nil || inst.Len == 0 {
			return insn{n: 1, text: "(bad)", bad: true}
		}
		if syntax == "gnu" {
			return insn{n: inst.Len, text: x86asm.GNUSyntax(inst, pc, nil)}
		}
		return insn{n: inst.Len, text: x86asm.IntelSyntax(inst, pc, nil)}
	case "arm":
		// x/arch's ARM decoder handles the 32-bit ARM instruction set only; Thumb is unsupported.
		inst, err := armasm.Decode(src, armasm.ModeARM)
		if err != nil || inst.Len == 0 {
			return insn{n: 4, text: "(bad)", bad: true}
		}
		return insn{n: inst.Len, text: armasm.GNUSyntax(inst)}
	case "arm64":
		inst, err := arm64asm.Decode(src)
		if err != nil {
			return insn{n: 4, text: "(bad)", bad: true}
		}
		return insn{n: 4, text: arm64asm.GNUSyntax(inst)}
	case "riscv64":
		inst, err := riscv64asm.Decode(src)
		if err != nil || inst.Len == 0 {
			return insn{n: 2, text: "(bad)", bad: true}
		}
		return insn{n: inst.Len, text: riscv64asm.GNUSyntax(inst)}
	case "ppc64", "ppc64le":
		var ord binary.ByteOrder = binary.BigEndian
		if arch == "ppc64le" {
			ord = binary.LittleEndian
		}
		inst, err := ppc64asm.Decode(src, ord)
		if err != nil || inst.Len == 0 {
			return insn{n: 4, text: "(bad)", bad: true}
		}
		return insn{n: inst.Len, text: ppc64asm.GNUSyntax(inst, pc)}
	}
	return insn{n: 1, text: "(unsupported architecture)", bad: true}
}

func disasm(this js.Value, args []js.Value) any {
	if len(args) < 5 {
		return js.ValueOf("expected (arch, bytes, baseAddr, maxInsns, syntax)")
	}
	arch := args[0].String()
	src := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(src, args[1])
	base := uint64(args[2].Float())
	max := args[3].Int()
	syntax := args[4].String()

	out := make([]any, 0, max)
	off := 0
	for len(out) < max && off < len(src) {
		in := decodeOne(arch, src[off:], base+uint64(off), syntax)
		n := in.n
		if n < 1 {
			n = 1
		}
		if off+n > len(src) {
			n = len(src) - off
		}
		var sb strings.Builder
		for _, b := range src[off : off+n] {
			fmt.Fprintf(&sb, "%02x", b)
		}
		out = append(out, map[string]any{
			"addr":    float64(base + uint64(off)),
			"off":     off,
			"len":     n,
			"bytes":   sb.String(),
			"text":    in.text,
			"bad":     in.bad,
			"partial": in.partial,
		})
		off += n
	}
	return js.ValueOf(out)
}

func main() {
	js.Global().Set("teardownDisasm", js.FuncOf(disasm))
	js.Global().Set("teardownDisasmReady", true)
	select {} // keep the Go runtime alive so the exported function stays callable
}
