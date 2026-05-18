// utils.go - 工具函数（字符串处理、文件检查、系统代理、证书管理）
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ======== 字符串工具函数 ========

func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	lines := strings.Split(s, "\n")
	// 移除末尾可能的空行
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		result = append(result, trimmed)
	}
	return result
}

func splitFields(s string) []string {
	return strings.Fields(s)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// ======== 文件工具函数 ========

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ======== 进程/命令工具函数 ========

func createCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// ======== 系统代理管理 ========

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func setProxy(enable bool, proxyServer string) bool {
	if proxyServer == "" {
		proxyServer = "127.0.0.1:8888"
	}

	modadvapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return false
	}
	procRegOpenKeyEx, err := modadvapi32.FindProc("RegOpenKeyExW")
	if err != nil {
		return false
	}
	procRegSetValueEx, err := modadvapi32.FindProc("RegSetValueExW")
	if err != nil {
		return false
	}
	procRegCloseKey, err := modadvapi32.FindProc("RegCloseKey")
	if err != nil {
		return false
	}

	// 打开注册表键 HKEY_CURRENT_USER
	keyPath, _ := syscall.UTF16PtrFromString(regPath)
	var hKey uintptr
	const (
		HKEY_CURRENT_USER = 0x80000001
		KEY_SET_VALUE     = 0x0002
		REG_DWORD         = 4
		REG_SZ            = 1
	)

	ret, _, _ := procRegOpenKeyEx.Call(
		HKEY_CURRENT_USER,
		uintptr(unsafe.Pointer(keyPath)),
		0,
		KEY_SET_VALUE,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		fmt.Printf("[ERROR] 无法打开注册表键: %d\n", ret)
		return false
	}
	defer procRegCloseKey.Call(hKey)

	// 设置 ProxyEnable
	proxyEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	value := uint32(0)
	if enable {
		value = 1
	}
	procRegSetValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(proxyEnable)),
		0,
		REG_DWORD,
		uintptr(unsafe.Pointer(&value)),
		4,
	)

	if enable {
		// 设置 ProxyServer
		proxyServerName, _ := syscall.UTF16PtrFromString("ProxyServer")
		proxyServerStr, _ := syscall.UTF16PtrFromString(proxyServer)
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(proxyServerName)),
			0,
			REG_SZ,
			uintptr(unsafe.Pointer(proxyServerStr)),
			uintptr((len(proxyServer)+1)*2),
		)

		// 设置 ProxyOverride
		override := `<local>;*.local;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*`
		proxyOverride, _ := syscall.UTF16PtrFromString("ProxyOverride")
		overrideStr, _ := syscall.UTF16PtrFromString(override)
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(proxyOverride)),
			0,
			REG_SZ,
			uintptr(unsafe.Pointer(overrideStr)),
			uintptr((len(override)+1)*2),
		)
	}

	// 通知系统代理设置已更改 (InternetSetOption)
	modwininet, err := syscall.LoadDLL("wininet.dll")
	if err == nil {
		procInternetSetOption, _ := modwininet.FindProc("InternetSetOptionW")
		const INTERNET_OPTION_SETTINGS_CHANGED = 39
		const INTERNET_OPTION_REFRESH = 37
		procInternetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
		procInternetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
	}

	return true
}

// ======== 证书管理 ========

func checkCertificateInstalled() bool {
	cmd := exec.Command("certutil", "-store", "-user", "Root")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(output)), "mitmproxy")
}

func showMessageBox(title, message string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	const MB_OK = 0
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(
		0,
		uintptr(unsafe.Pointer(msgPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		MB_OK,
	)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
