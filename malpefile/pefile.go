package malpefile

import (
	//"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"github.com/saferwall/pe"
	"strconv"
)

type PEFile struct {
	filename string
	peidPath string
	peFile   *pe.File
	logger   Logger
	Data     Result
}

func NewPEFile(filename, peidPath string, logger Logger) (*PEFile, error) {

	exe, err := pe.New(filename, nil)
	if err != nil {
		logger.Errorf("Error while opening file: %s, reason: %v", filename, err)
		return nil, err
	}

	err = exe.Parse()
	if err != nil {
		logger.Errorf("Error while parsing file: %s, reason: %v", filename, err)
		return nil, err
	}

	peFile := &PEFile{
		filename: filename,
		peidPath: peidPath,
		peFile:   exe,
		logger:   logger,
	}
	return peFile, nil
}

func (p *PEFile) Debug() {
	if len(p.peFile.Debugs) == 0 {
		return
	}
	//p.Data.Debug.TimeDateStamp = p.peFile.Debugs.
}

func (p *PEFile) Run() {
	p.Info()
	p.RichHeaderInfo()
	p.ImpHash()
	p.Section()
	p.DataDirectory()
	p.Import()

	// exports
	p.Export()
	p.ExportsTimestamp()
	p.ExportsModuleName()
}

func Uint32ToHex(i uint32) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return hex.EncodeToString(buf)
}

func Hex(i uint64) string {
	return "0x" + strconv.FormatUint(i, 16)
}
