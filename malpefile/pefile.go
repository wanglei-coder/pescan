package malpefile

import (
	"github.com/saferwall/pe"
)

type PEFile struct {
	filename string
	peidPath string
	peFile   *pe.File
	logger   Logger
	Data     Result
}

func NewPEFile(filename, peidPath string, logger Logger) (*PEFile, error) {

	exe, err := pe.New(filename, &pe.Options{SectionEntropy: true})
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

	// import
	p.Import()

	// exports
	p.Export()
	p.ExportsTimestamp()
	p.ExportsModuleName()

	// resources
	p.Resources()

	// signature
	p.Signature()
}
