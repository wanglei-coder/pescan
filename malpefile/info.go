package malpefile

import (
	"fmt"
	"github.com/saferwall/pe"
	"time"
)

func (p *PEFile) Info() {
	p.getInfoFromOptionHeader()
	p.Data.Info.CompileTime = compileTime(p.peFile)
	//p.entrypoint()

	p.Data.Info.NumberOfSections = p.peFile.NtHeader.FileHeader.NumberOfSections

	machine := p.peFile.NtHeader.FileHeader.Machine
	p.Data.Info.MachineType = fmt.Sprintf("0x%x (%s)", machine, MachineType[int(machine)])
}

func (p *PEFile) getInfoFromOptionHeader() {
	if p.peFile.Is64 {
		OptionalHeader := p.peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
		p.Data.Info.EntryPoint = Hex(uint64(OptionalHeader.AddressOfEntryPoint))
		p.Data.Info.ImageBase = int(OptionalHeader.ImageBase)
		p.Data.Info.SizeOfImage = OptionalHeader.SizeOfImage
		p.Data.Info.LinkerVersion = uint16(OptionalHeader.MajorLinkerVersion) + uint16(OptionalHeader.MinorLinkerVersion)
		p.Data.Info.OsVersion = uint32(OptionalHeader.MajorOperatingSystemVersion) + uint32(OptionalHeader.MinorOperatingSystemVersion)
	} else {
		OptionalHeader := p.peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
		p.Data.Info.EntryPoint = Hex(uint64(OptionalHeader.AddressOfEntryPoint))
		p.Data.Info.ImageBase = int(OptionalHeader.ImageBase)
		p.Data.Info.SizeOfImage = OptionalHeader.SizeOfImage
		p.Data.Info.LinkerVersion = uint16(OptionalHeader.MajorLinkerVersion) + uint16(OptionalHeader.MinorLinkerVersion)
		p.Data.Info.OsVersion = uint32(OptionalHeader.MajorOperatingSystemVersion) + uint32(OptionalHeader.MinorOperatingSystemVersion)

	}

}

func entrypoint(peFile *pe.File) string {
	if peFile.Is64 {
		OptionalHeader := peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
		return Hex(uint64(OptionalHeader.AddressOfEntryPoint))
	} else {
		OptionalHeader := peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
		return Hex(uint64(OptionalHeader.AddressOfEntryPoint))
	}
}

func compileTime(peFile *pe.File) CompileTime {
	unix := peFile.NtHeader.FileHeader.TimeDateStamp
	dateTime := time.Unix(int64(unix), 0).Format("2006-01-02 03:04:05")
	cTime := CompileTime{
		Unix:     unix,
		DateTime: dateTime,
	}
	return cTime
}
