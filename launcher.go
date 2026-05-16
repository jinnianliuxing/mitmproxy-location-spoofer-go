// launcher.go - 极简启动器（无计划任务，保留UAC，单窗口无闪黑）
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

const mutexName = "Global\\MitmproxyLocationSpooferMutex_v3"

func isAdmin() bool {
	modshell32, err := syscall.LoadDLL("shell32.dll")
	if err != nil {
		return false
	}
	procIsUserAnAdmin, err := modshell32.FindProc("IsUserAnAdmin")
	if err != nil {
		return false
	}
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

func hideConsoleWindow() {
	hwnd, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	if hwnd != 0 {
		syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(hwnd, 0)
	}
}

func showConsoleWindow() {
	hwnd, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	if hwnd != 0 {
		syscall.NewLazyDLL("user32.dll").NewProc("ShowWindow").Call(hwnd, 5)
	}
}

// checkAndCleanAbnormalProxy 检查并清理异常的代理设置
func checkAndCleanAbnormalProxy() {
	// 检查当前代理是否指向我们的端口但程序未运行
	modadvapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return
	}
	procRegOpenKeyEx, err := modadvapi32.FindProc("RegOpenKeyExW")
	if err != nil {
		return
	}
	procRegQueryValueEx, err := modadvapi32.FindProc("RegQueryValueExW")
	if err != nil {
		return
	}
	procRegCloseKey, err := modadvapi32.FindProc("RegCloseKey")
	if err != nil {
		return
	}

	const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	keyPath, _ := syscall.UTF16PtrFromString(regPath)
	var hKey uintptr
	const (
		HKEY_CURRENT_USER = 0x80000001
		KEY_QUERY_VALUE   = 0x0001
		REG_DWORD         = 4
		REG_SZ            = 1
	)

	ret, _, _ := procRegOpenKeyEx.Call(
		HKEY_CURRENT_USER,
		uintptr(unsafe.Pointer(keyPath)),
		0,
		KEY_QUERY_VALUE,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return
	}
	defer procRegCloseKey.Call(hKey)

	// 查询 ProxyEnable
	proxyEnableName, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var enableValue uint32
	var enableType uint32
	var enableSize uint32 = 4
	procRegQueryValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(proxyEnableName)),
		0,
		uintptr(unsafe.Pointer(&enableType)),
		uintptr(unsafe.Pointer(&enableValue)),
		uintptr(unsafe.Pointer(&enableSize)),
	)

	if enableType == REG_DWORD && enableValue == 1 {
		// 代理已启用，检查 ProxyServer
		proxyServerName, _ := syscall.UTF16PtrFromString("ProxyServer")
		var serverType uint32
		var serverSize uint32 = 1024
		serverBuffer := make([]uint16, 512)
		ret, _, _ := procRegQueryValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(proxyServerName)),
			0,
			uintptr(unsafe.Pointer(&serverType)),
			uintptr(unsafe.Pointer(&serverBuffer[0])),
			uintptr(unsafe.Pointer(&serverSize)),
		)

		if ret == 0 && serverType == REG_SZ && serverSize > 0 {
			serverStr := syscall.UTF16ToString(serverBuffer[:serverSize/2])
			// 检查是否指向我们的代理端口
			if serverStr == "127.0.0.1:8888" || serverStr == "localhost:8888" {
				// 检查我们的代理服务是否真的在运行
				if !proxyIsRunning() {
					fmt.Println("[INFO] 检测到异常代理设置，正在清理...")
					setProxy(false, "")
					fmt.Println("[OK] 异常代理设置已清理")
				}
			}
		}
	}
}

// runAsAdminAndExit UAC提权，成功后当前进程退出
func runAsAdminAndExit() {
	if isAdmin() {
		return
	}
	hideConsoleWindow()

	exePath, _ := os.Executable()
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString("")

	ret, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		0, 1,
	)
	if ret > 32 {
		os.Exit(0)
	}
	showConsoleWindow()
	fmt.Printf("[ERROR] 无法获取管理员权限\n")
	time.Sleep(2)
	os.Exit(1)
}

// proxyIsRunning 通过连接 8888 端口检测代理是否在运行
func proxyIsRunning() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8888", 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var mutexHandle uintptr

func acquireMutex() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW := kernel32.NewProc("CreateMutexW")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	procGetLastError := kernel32.NewProc("GetLastError")

	namePtr, _ := syscall.UTF16PtrFromString(mutexName)
	handle, _, _ := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		return false
	}

	const ERROR_ALREADY_EXISTS = 183
	lastErr, _, _ := procGetLastError.Call()
	if lastErr == ERROR_ALREADY_EXISTS {
		procCloseHandle.Call(handle)
		return false
	}
	mutexHandle = handle
	return true
}

func releaseMutex() {
	if mutexHandle != 0 {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		procCloseHandle := kernel32.NewProc("CloseHandle")
		procCloseHandle.Call(mutexHandle)
		mutexHandle = 0
	}
}

func openWechatMiniprogram() {
	url := "weixin://launchapplet/?app_id=wx0e47c34c9982aa09"
	verb, _ := syscall.UTF16PtrFromString("open")
	urlW, _ := syscall.UTF16PtrFromString(url)
	syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(urlW)),
		0, 0, 1,
	)
}

// cleanupOnExit 确保退出时清理代理设置
func cleanupOnExit() {
	// 注册退出清理函数
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-c
		setProxy(false, "")
		os.Exit(0)
	}()
}

// 启动器主函数
// 流程：
// 1. 启动时检查异常代理设置并清理
// 2. 端口已开 → 代理在运行 → 打开小程序 → 退出（不弹UAC）
// 3. 端口未开 + 管理员 → 获取互斥体 → 启动代理
// 4. 端口未开 + 普通进程 → 先抢互斥体（阻止其他普通进程） → UAC提权
func runLauncher(isScheduled bool) {
	// 启动时检查并清理异常代理设置
	checkAndCleanAbnormalProxy()

	// 端口检测：代理已在运行 → 打开小程序退出
	if proxyIsRunning() {
		hideConsoleWindow()
		openWechatMiniprogram()
		time.Sleep(500 * time.Millisecond) // 给小程序启动一点时间
		return
	}

	if isAdmin() {
		// 管理员进程 → 互斥体防止多次启动
		if !acquireMutex() {
			// 已有实例在运行，隐藏窗口并打开小程序
			hideConsoleWindow()
			openWechatMiniprogram()
			time.Sleep(500 * time.Millisecond)
			return
		}
		fmt.Println("=" + repeat("=", 58))
		fmt.Println("  Mitmproxy 定位伪造工具 - Pure Go")
		fmt.Println("=" + repeat("=", 58))

		// 设置退出清理
		cleanupOnExit()
		
		runProxy()
		releaseMutex()
		return
	}

	// ★ 普通进程 → 先抢互斥体（防止多个普通进程同时UAC）
	if !acquireMutex() {
		// 互斥体被占用 → 另一个实例正在运行 → 隐藏窗口并打开小程序
		hideConsoleWindow()
		openWechatMiniprogram()
		time.Sleep(500 * time.Millisecond)
		return
	}
	// 释放互斥体（管理员进程会重新获取）
	releaseMutex()

	// UAC提权
	runAsAdminAndExit()
}