package malpefile

import (
	debugPE "debug/pe"
	"encoding/json"
	"fmt"
	"github.com/gonutz/w32/v2"
	"github.com/uniplaces/carbon"
	"go.uber.org/zap"
	"path/filepath"
	"pescan/pe"
	"reflect"
	"testing"
	"time"
)

var defaultLogger = zap.NewExample().Sugar()

func TestDebugPes(tt *testing.T) {
	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	size := w32.GetFileVersionInfoSize(path)
	if size <= 0 {
		panic("GetFileVersionInfoSize failed")
	}

	info := make([]byte, size)
	ok := w32.GetFileVersionInfo(path, info)
	if !ok {
		panic("GetFileVersionInfo failed")
	}

	fixed, ok := w32.VerQueryValueRoot(info)
	if !ok {
		panic("VerQueryValueRoot failed")
	}
	version := fixed.FileVersion()
	fmt.Printf(
		"file version: %d.%d.%d.%d\n",
		version&0xFFFF000000000000>>48,
		version&0x0000FFFF00000000>>32,
		version&0x00000000FFFF0000>>16,
		version&0x000000000000FFFF>>0,
	)

	translations, ok := w32.VerQueryValueTranslations(info)
	if !ok {
		panic("VerQueryValueTranslations failed")
	}
	if len(translations) == 0 {
		panic("no translation found")
	}
	fmt.Println("translations:", translations)

	t := translations[0]
	// w32.CompanyName simply translates to "CompanyName"
	company, ok := w32.VerQueryValueString(info, t, w32.CompanyName)
	if !ok {
		panic("cannot get company name")
	}
	fmt.Println("company:", company)

	FileDescription, ok := w32.VerQueryValueString(info, t, w32.FileDescription)
	FileVersion, ok := w32.VerQueryValueString(info, t, w32.FileVersion)
	LegalCopyright, ok := w32.VerQueryValueString(info, t, w32.LegalCopyright)
	LegalTrademarks, ok := w32.VerQueryValueString(info, t, w32.LegalTrademarks)
	OriginalFilename, ok := w32.VerQueryValueString(info, t, w32.OriginalFilename)
	ProductVersion, ok := w32.VerQueryValueString(info, t, w32.ProductVersion)
	PrivateBuild, ok := w32.VerQueryValueString(info, t, w32.PrivateBuild)
	SpecialBuild, ok := w32.VerQueryValueString(info, t, w32.SpecialBuild)
	fmt.Println("FileDescription: ", FileDescription)
	fmt.Println("FileVersion: ", FileVersion)
	fmt.Println("LegalCopyright: ", LegalCopyright)
	fmt.Println("LegalTrademarks: ", LegalTrademarks)
	fmt.Println("OriginalFilename: ", OriginalFilename)
	fmt.Println("ProductVersion: ", ProductVersion)
	fmt.Println("PrivateBuild: ", PrivateBuild)
	fmt.Println("SpecialBuild: ", SpecialBuild)
}

func TestDebugPe(t *testing.T) {
	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	//path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	peFile, err := debugPE.Open(path)
	if err != nil {
		t.Error(err)
	}
	data, _ := json.Marshal(peFile)
	t.Log(string(data))
}

func TestNewPEFile(t *testing.T) {
	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	//path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	fmt.Println(string(m.peFile.Header))
	m.Run()
	data, _ := json.Marshal(m.Data)
	t.Log("\n" + string(data))
}

func TestPEFile_ImpHash(t *testing.T) {
	//path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	path := "C:\\Users\\86187\\Downloads\\WeChatSetup.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	h, _ := m.peFile.ImpHash()

	t.Log(h)
}

func TestGetType(t *testing.T) {
	//path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	path := "C:\\Users\\86187\\Downloads\\Everything-1.4.1.1009.x64-Setup.exe"
	//path := "C:\\Users\\13939\\Downloads\\PCQQ2021.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	resourceList := getResources(m.peFile)
	for _, r := range resourceList {
		t.Logf("%+v", r)
	}
}

func TestSignature(t *testing.T) {
	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	//path := "C:\\Users\\13939\\Downloads\\PCQQ2021.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	exe := m.peFile
	s := getSignature(exe)
	data, _ := json.Marshal(s)
	fmt.Println(string(data))
}

func TestLang(t *testing.T) {
	l, ok := LANG[1]
	t.Log(l, ok, reflect.TypeOf(1))
}

func TestCOFF(t *testing.T) {
	//path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	//Filename := "C:\\Users\\86187\\Downloads\\PCQQ2021.exe"
	filename := "C:\\Users\\13939\\Downloads\\PCQQ2021.exe"

	exe, err := pe.New(filename, &pe.Options{
		Fast:           false,
		SectionEntropy: true,
	})
	if err != nil {
		defaultLogger.Errorf("Error while opening file: %s, reason: %v", filename, err)
		return
	}

	err = exe.Parse()
	if err != nil {
		defaultLogger.Errorf("Error while parsing file: %s, reason: %v", filename, err)
		return
	}

	//err = exe.ParseCOFFSymbolTable()
	//if err != nil {
	//	defaultLogger.Error(err)
	//}

	fmt.Println(exe.PrettyDllCharacteristics())
	fmt.Println(exe.PrettyImageFileCharacteristics())
	fmt.Println(exe.PrettySubsystem())

	data, _ := json.Marshal(exe.COFF)
	t.Log(string(data))
}

func TestUint32ToHex(t *testing.T) {
	//i := uint32(4194304)
	//fmt.Println(Uint32ToHex(i))
	//fmt.Println(strconv.FormatUint(uint64(i), 16))
	//path := "C:\\Users\\86187\\Downloads\\BaiduNetdisk_7.4.0.8.exe"
	//m, _ := NewPEFile(path, path, defaultLogger)
	//m.Import()
	//fmt.Printf("%+v\n", m.Data.Import)
	//
	//fmt.Println(MachineType[0])

	//fmt.Printf("%+v", m.peFile.RichHeader)

	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	//path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	//path := "C:\\Users\\13939\\Downloads\\goland-2020.3.1.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	m.Run()
	data, _ := json.Marshal(m.Data)
	t.Log(string(data))
	t.Log(m.Data.ExportsTimestamp)
	//data, _ = json.Marshal(m.peFile)
	//_ = ioutil.WriteFile("E:\\pe.json", data, os.ModeAppend)
	//t.Log(string(data))

	//exe, err := pe.Open(path)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//
	//fmt.Println("exe.NtHeader.FileHeader.Characteristics: ", exe.FileHeader.Characteristics)
	//fmt.Println("exe.NtHeader.FileHeader.Characteristics: ", exe.FileHeader.Machine)
	//fmt.Printf("%+v\n", exe)
	//data, _ := json.Marshal(exe)
	//fmt.Println(string(data))
}

func TestTimeStampToDate(t *testing.T) {
	timestamp := 1621935220
	c, err := carbon.CreateFromTimestamp(int64(timestamp), "UTC")
	t.Log(c, err)
}

func TestCert(t *testing.T) {
	s := &Signer{
		CertValidTo:   "2024-02-22T23:59:59+00:00",
		CertSerialNo:  "18874367992585516799620967379699280448",
		CertValidFrom: "2020-11-25T00:00:00+00:00",
		CertVersion:   0,
		CertSubject:   "CN=Tencent",
		CertIssuer:    "CN=DigiCert",
	}

	ss := []*Signer{s}
	os := []*Signer{s}

	c := &Cert{
		Signers: ss,
		Others:  os,
	}

	cs := []*Cert{c}

	signature := Signature{
		Heuristic: "sda",
		Certs:     cs,
	}
	data, _ := json.Marshal(signature)
	fmt.Println(string(data))
}

func TestTimeformat(t *testing.T) {
	tf := time.Now()
	t.Log(tf.Format("2006-01-02T15:04:05+00:00"))
}

func TestFormat(t *testing.T) {
	a := fmt.Sprintf("%02d.%02d", uint8(14), 0)
	t.Log(a)
}

func TestGetPEFileInfo(t *testing.T) {
	pattern := "C:\\Users\\86187\\Downloads\\*.exe"
	//pattern := "E:\\VirusSample\\病毒样本\\天津检测样本\\天津检测中心病毒样本\\流行库\\B4流行库NEW（210-210）\\*.exe"
	fileNameList, err := filepath.Glob(pattern)
	if err != nil {
		t.Log(err)
		return
	}
	for _, fileName := range fileNameList {
		res, _ := GetPEFileInfo(fileName, fileName, defaultLogger)
		data, _ := json.Marshal(res)
		fmt.Println(fileName + "------------------\n" + string(data))
	}
}

func TestHex(t *testing.T) {
	//path := "C:\\Users\\86187\\Downloads\\Everything-1.4.1.1009.x64-Setup.exe"
	path := "E:\\VirusSample\\病毒样本\\天津检测样本\\天津检测中心病毒样本\\流行库\\B4流行库NEW（210-210）\\new057.exe"
	f, err := debugPE.Open(path)
	if err != nil {
		t.Log(err)
	}
	data, _ := json.Marshal(f)
	fmt.Println(string(data))

	exe, err := pe.New(path, nil)
	if err != nil {
		t.Log(err)
	}
	err = exe.Parse()
	if err != nil {
		t.Log("parse: ", err)
	}
	data, _ = json.Marshal(exe)
	fmt.Println(string(data))

	res, _ := GetPEFileInfo(path, path, defaultLogger)
	fmt.Printf("%+v\n", res)
	data, _ = json.Marshal(res)
	fmt.Println(string(data))
}
