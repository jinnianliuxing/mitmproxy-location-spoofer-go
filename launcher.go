// launcher.go - 极简启动器（无计划任务，保留UAC，单窗口无闪黑）
// 修复: 跨权限Mutex + explorer中继打开小程序 + 失败弹窗
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
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

// 文件锁路径 — 作为 Mutex 的兜底机制，确保跨权限会话可见
func getLockFilePath() string {
	return filepath.Join(os.TempDir(), ".mitmproxy_spoofer_launcher.lock")
}

// acquireFileLock 使用文件锁作为跨权限单实例兜底检测
// Windows 上 TEMP 目录所有用户可访问，文件锁天然跨会话
func acquireFileLock() (bool, uintptr) {
	lockPath := getLockFilePath()
	pathPtr, _ := syscall.UTF16PtrFromString(lockPath)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW := kernel32.NewProc("CreateFileW")

	const (
		GENERIC_READ          = 0x80000000
		GENERIC_WRITE         = 0x40000000
		FILE_SHARE_READ       = 0x00000001
		FILE_SHARE_WRITE      = 0x00000002
		OPEN_ALWAYS           = 4
		FILE_ATTRIBUTE_NORMAL = 0x80
		INVALID_HANDLE_VALUE  = ^uintptr(0)
	)

	// 以独占写入模式打开：只允许其他进程读，不允许写
	// 第二个进程打开会返回 INVALID_HANDLE_VALUE
	handle, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ, // 只共享读，不共享写 → 实现互斥
		0,               // 默认安全属性（继承自 TEMP 目录权限）
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if handle == INVALID_HANDLE_VALUE {
		return false, 0
	}
	return true, handle
}

var mutexHandle uintptr
var fileLockHandle uintptr

// acquireMutex 获取全局互斥体 — 修复跨权限不可见问题
// 使用 OpenMutexW + CreateMutexW 双重检测，处理 ERROR_ACCESS_DENIED
func acquireMutex() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW := kernel32.NewProc("CreateMutexW")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	procGetLastError := kernel32.NewProc("GetLastError")
	procOpenMutexW := kernel32.NewProc("OpenMutexW")

	namePtr, _ := syscall.UTF16PtrFromString(mutexName)

	const (
		SYNCHRONIZE          = 0x00100000
		ERROR_ALREADY_EXISTS = 183
		ERROR_ACCESS_DENIED  = 5
	)

	// ★ 步骤1: 先尝试 OpenMutexW 检测是否已有实例
	// 使用 OpenMutexW 代替 CreateMutexW 进行检测，避免权限问题
	existingHandle, _, _ := procOpenMutexW.Call(
		SYNCHRONIZE,
		0,
		uintptr(unsafe.Pointer(namePtr)),
	)

	if existingHandle != 0 {
		// 有已有实例 → 释放句柄，返回 false
		procCloseHandle.Call(existingHandle)
		return false
	}

	// ★ 步骤2: 如果没有已有实例，尝试创建
	handle, _, _ := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		// 创建也失败 → 用文件锁兜底
		return fallbackFileLock()
	}

	lastErr, _, _ := procGetLastError.Call()
	if lastErr == ERROR_ALREADY_EXISTS {
		// 在 OpenMutexW 和 CreateMutexW 之间被创建了
		procCloseHandle.Call(handle)
		return false
	}

	if lastErr == ERROR_ACCESS_DENIED {
		// ★ 关键修复: 管理员已创建 Mutex 且普通进程无法访问
		// 释放创建失败的句柄，使用文件锁兜底检测
		procCloseHandle.Call(handle)
		return fallbackFileLock()
	}

	// 创建成功，保存句柄
	mutexHandle = handle
	return true
}

// fallbackFileLock 文件锁兜底方案 — 当 Mutex 因权限不可见时使用
func fallbackFileLock() bool {
	ok, handle := acquireFileLock()
	if ok {
		fileLockHandle = handle
		return true
	}
	// 文件锁也失败 → 说明另一个实例持有锁
	return false
}

func releaseMutex() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle := kernel32.NewProc("CloseHandle")

	// 释放 Mutex 句柄
	if mutexHandle != 0 {
		procCloseHandle.Call(mutexHandle)
		mutexHandle = 0
	}

	// 释放文件锁句柄
	if fileLockHandle != 0 {
		procCloseHandle.Call(fileLockHandle)
		fileLockHandle = 0
	}
}

// openWechatMiniprogram 打开微信小程序
// ★ 修复: 非管理员进程直接调用 weixin://，管理员进程通过 explorer.exe 中继
// Windows UAC UIPI 阻止高完整性进程调用低完整性协议处理器，
// explorer.exe 始终运行于桌面中等完整性级别，可作为中继使用
func openWechatMiniprogram() {
	url := "weixin://launchapplet/?app_id=wx0e47c34c9982aa09"
	verbPtr, _ := syscall.UTF16PtrFromString("open")
	urlW, _ := syscall.UTF16PtrFromString(url)

	if isAdmin() {
		// ★ 管理员进程 → ShellExecuteW("explorer.exe", "weixin://...")
		// explorer.exe 以用户中完整性运行，将 weixin:// 协议分派给微信客户端
		explorerPath, _ := syscall.UTF16PtrFromString("explorer.exe")
		syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
			0,
			uintptr(unsafe.Pointer(verbPtr)),
			uintptr(unsafe.Pointer(explorerPath)),
			uintptr(unsafe.Pointer(urlW)),
			0, 1,
		)
		return
	}

	// ★ 非管理员进程 → 直接用 ShellExecuteW（weixin:// 协议正常工作）
	syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
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

// runAsAdminAndExit UAC提权，成功后当前进程退出
// ★ 修复: 失败时用 MessageBox 弹窗提示用户
func runAsAdminAndExit() {
	if isAdmin() {
		return
	}

	exePath, _ := os.Executable()
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString("")

	// ★ 不要在提权前隐藏窗口！否则用户看不到错误
	ret, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		0, 1,
	)
	if ret > 32 {
		// UAC 提权请求已发送，当前进程退出（管理员进程启动新窗口）
		os.Exit(0)
	}

	// ★ 提权失败 → 保持窗口可见，弹 MessageBox 提示
	showConsoleWindow()
	showMessageBox("权限提升失败",
		"无法获取管理员权限运行代理服务，程序将退出。\n\n"+
			"可能的原因：\n"+
			"1. 您点击了 UAC 提示框的「否」\n"+
			"2. 系统策略禁用了 UAC 提权弹窗\n"+
			"3. 当前账户权限不足\n\n"+
			"解决方法：\n"+
			"• 右键程序 →「以管理员身份运行」\n"+
			"• 或在命令行中以管理员身份执行")

	fmt.Printf("[ERROR] 无法获取管理员权限: ShellExecuteW 返回 %d\n", ret)
	time.Sleep(3 * time.Second)
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

// 启动器主函数（★修复: weixin:// 协议在 UAC 提权前从非管理员进程调用）
// 流程：
//  1. 启动时检查异常代理设置并清理
//  2. 端口已开 → 代理在运行 → 打开小程序 → 退出（不弹UAC）
//  3. 端口未开 + 管理员 → 获取互斥体 → 启动代理（代理内部自动打开小程序）
//  4. 端口未开 + 普通进程 → 先打开小程序（从非管理员进程，weixin://正常工作）
//     然后UAC提权，管理员进程自动启动代理并再次打开小程序
func runLauncher(_ bool) {
	// 启动时检查并清理异常代理设置
	checkAndCleanAbnormalProxy()

	// 端口检测：代理已在运行 → 打开小程序退出
	if proxyIsRunning() {
		hideConsoleWindow()
		openWechatMiniprogram()
		time.Sleep(500 * time.Millisecond)
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

	// ★ 普通进程 → 先抢互斥体（修复: Mutex 不可见时文件锁兜底）
	if !acquireMutex() {
		// 互斥体被占用 → 另一个实例正在运行 → 隐藏窗口并打开小程序
		hideConsoleWindow()
		openWechatMiniprogram()
		time.Sleep(500 * time.Millisecond)
		return
	}
	// 释放互斥体（管理员进程会重新获取）
	releaseMutex()

	// ★ 关键修复: 在 UAC 提权前先打开 weixin://
	// 此时进程还是非管理员，ShellExecuteW 调用 weixin:// 协议不会被 UIPI 拦截
	// 提权后将由管理员进程启动代理，代理内部 runProxy() 会再次调用 openWechatMiniprogram()
	// 第二次调用虽然因 UIPI 可能失败，但小程序已经被第一次调用打开了
	if !proxyIsRunning() {
		fmt.Println("[*] 正在打开微信小程序（非管理员权限）...")
		openWechatMiniprogram()
	}

	// UAC提权
	runAsAdminAndExit()
}
