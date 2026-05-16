// watchdog.go - 代理看门狗（Go 版，独立进程模式）
// 监控代理进程（通过端口检测），服务停止后自动关闭代理
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// 检查代理是否在运行（通过连接端口检测）
func checkProxyRunning() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8888", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 关闭当前进程
func closeSelf() {
	pid := os.Getpid()
	cmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid))
	cmd.Run()
}

// 看门狗主函数（独立进程模式）
func runWatchdog() {
	fmt.Println("=" + repeat("=", 38))
	fmt.Println("  代理看门狗监控器已启动")
	fmt.Println("  检测到服务停止将自动关闭代理，防止网络错误")
	fmt.Println("  不要提前关闭此窗口，程序会自动关闭")
	fmt.Println("=" + repeat("=", 38))

	time.Sleep(300 * time.Millisecond)

	serviceDetected := false
	consecutiveFailures := 0
	maxFailures := 3
	checkInterval := 1.0

	for {
		isRunning := checkProxyRunning()

		if isRunning {
			if !serviceDetected {
				fmt.Println("  [状态] 主服务已运行")
			}
			serviceDetected = true
			consecutiveFailures = 0
			checkInterval = 2.0
		} else if serviceDetected {
			consecutiveFailures++
			checkInterval = 1.0

			if consecutiveFailures >= maxFailures {
				fmt.Println("  [状态] 检测到服务停止，正在关闭代理...")
				setProxy(false, "")
				time.Sleep(200 * time.Millisecond)
				fmt.Println("  [状态] 代理已关闭，看门狗退出")
				closeSelf()
				break
			}
		}

		time.Sleep(time.Duration(checkInterval * float64(time.Second)))
	}

	os.Exit(0)
}