package malpefile

import (
	"go.uber.org/zap"
	"pescan/pe"
	"time"
)

type PEFile struct {
	Filename string
	peidPath string
	peFile   *pe.File
	logger   Logger
	Data     Result
}

func NewPEFile(filename, peidPath string, logger Logger) (*PEFile, error) {

	if logger == nil {
		_logger, _ := zap.NewProduction()
		logger = _logger.Sugar()
	}

	exe, err := pe.New(filename, &pe.Options{SectionEntropy: true})
	if err != nil {
		logger.Errorf("Error while opening file: %s, reason: %v", filename, err)
		return nil, err
	}

	err = exe.Parse()
	if err != nil {
		logger.Errorf("Error while parsing file: %s, reason: %v", filename, err)
	}

	peFile := &PEFile{
		Filename: filename,
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
	p.ResourceVersionInfo()

	// signature
	p.Signature()
}

func (p *PEFile) RunWithTimeCost() *Result {
	startTime := time.Now()
	p.Run()
	endTime := time.Now()
	timeCost := endTime.Sub(startTime)
	p.logger.Infof("fileName: %s, Cost Time: %s", p.Filename, timeCost)
	return &p.Data
}

func GetPEFileInfo(filename, peidPath string, logger Logger) (*Result, error) {
	peFile, err := NewPEFile(filename, peidPath, logger)
	if err != nil {
		return nil, err
	}

	peFile.Run()
	return &peFile.Data, nil
}
