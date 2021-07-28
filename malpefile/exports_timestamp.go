package malpefile

import (
	"github.com/saferwall/pe"
	"github.com/uniplaces/carbon"
	"time"
)

func (p *PEFile) ExportsTimestamp() {

	p.Data.ExportsTimestamp = getExportsTimestamp(p.peFile)

}

func getExportsTimestamp(peFile *pe.File) string {
	if peFile.Export == nil {
		return ""
	}

	dateTime, err := carbon.CreateFromTimestampUTC(int64(peFile.Export.Struct.TimeDateStamp))
	if err != nil {
		return ""
	}

	return dateTime.Format(time.ANSIC)
}
