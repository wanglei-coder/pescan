package malpefile

import (
	"bytes"
	"encoding/binary"
	"github.com/saferwall/pe"
	"go.mozilla.org/pkcs7"
	"reflect"
)

func (p *PEFile) Signature() {
	p.Data.Signature = getSignature(p.peFile)
}

func getSignature(peFile *pe.File) Signature {
	oh32 := pe.ImageOptionalHeader32{}
	oh64 := pe.ImageOptionalHeader64{}

	switch peFile.Is64 {
	case true:
		oh64 = peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
	case false:
		oh32 = peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
	}

	var cert Cert
	for entryIndex := 0; entryIndex < pe.ImageNumberOfDirectoryEntries; entryIndex++ {
		var va, size uint32
		switch peFile.Is64 {
		case true:
			dirEntry := oh64.DataDirectory[entryIndex]
			va = dirEntry.VirtualAddress
			size = dirEntry.Size
		case false:
			dirEntry := oh32.DataDirectory[entryIndex]
			va = dirEntry.VirtualAddress
			size = dirEntry.Size
		}

		if va != 0 {
			_ = parseSecurityDirectory(va, size, peFile, &cert)
		}
	}
	var signature Signature
	var heuristic string
	if peFile.Certificates != nil {
		heuristic = "This PE appears to have a legitimate signature"
	} else {
		heuristic = ""
	}
	signature.Heuristic = heuristic
	signature.Certs = []*Cert{&cert}

	return signature
}

func parseSecurityDirectory(rva, size uint32, peFile *pe.File, customCert *Cert) error {
	var pkcs *pkcs7.PKCS7
	//var isValid bool
	//certInfo := pe.CertInfo{}
	certHeader := pe.WinCertificate{}
	certSize := uint32(binary.Size(certHeader))

	fileOffset := rva

	for {
		err := structUnpack(&certHeader, fileOffset, certSize, peFile)
		if err != nil {
			return err
		}

		certContent, err := peFile.ReadBytesAtOffset(fileOffset+certSize, certHeader.Length-certSize)
		if err != nil {
			return err
		}

		pkcs, err = pkcs7.Parse(certContent)
		if err != nil {
			return err
		}

		serialNumber := pkcs.Signers[0].IssuerAndSerialNumber.SerialNumber
		for _, cert := range pkcs.Certificates {
			signer := &Signer{
				CertValidTo:   cert.NotAfter.Format("2006-01-02T15:04:05+00:00"),
				CertSerialNo:  cert.SerialNumber.String(),
				CertValidFrom: cert.NotBefore.Format("2006-01-02T15:04:05+00:00"),
				CertVersion:   cert.Version,
				CertSubject:   cert.Subject.String(),
				CertIssuer:    cert.Issuer.String(),
			}
			if reflect.DeepEqual(cert.SerialNumber, serialNumber) {
				customCert.Signers = append(customCert.Signers, signer)
			} else {
				customCert.Others = append(customCert.Others, signer)
			}
		}

		nextOffset := certHeader.Length + fileOffset
		nextOffset = ((nextOffset + 8 - 1) / 8) * 8

		if nextOffset == fileOffset+size {
			break
		}

		fileOffset = nextOffset
	}
	return nil
}

func structUnpack(iface interface{}, offset, size uint32, peFile *pe.File) error {

	data, err := peFile.ReadBytesAtOffset(offset, size)
	if err != nil {
		return err
	}

	buf := bytes.NewReader(data)
	if err = binary.Read(buf, binary.LittleEndian, iface); err != nil {
		return err
	}

	return nil
}
