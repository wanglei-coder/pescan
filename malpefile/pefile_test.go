package malpefile

import (
	debugPE "debug/pe"
	"encoding/json"
	"fmt"
	"github.com/saferwall/pe"
	"github.com/uniplaces/carbon"
	"go.uber.org/zap"
	"reflect"
	"testing"
)

var defaultLogger = zap.NewExample().Sugar()

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
	path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	data, _ := json.Marshal(m.peFile)
	t.Log(string(data))
	t.Log(len(m.peFile.IAT))
}

func TestGetType(t *testing.T) {
	path := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"
	m, err := NewPEFile(path, path, defaultLogger)
	if err != nil {
		defaultLogger.Error(err)
		return
	}
	getResources(m.peFile)
}

func TestLang(t *testing.T) {
	l, ok := LANG[1]
	t.Log(l, ok, reflect.TypeOf(1))
}

func TestCOFF(t *testing.T) {
	//path := "C:\\Users\\86187\\Downloads\\goland-2020.3.1.exe"
	filename := "C:\\Users\\86187\\Downloads\\QQMusicSetup.exe"

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
