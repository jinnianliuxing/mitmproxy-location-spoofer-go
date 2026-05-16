// main.go - Mitmproxy Location Spoofer (Pure Go, 单文件独立运行)
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// 定义命令行参数
	scheduledFlag := flag.Bool("scheduled", false, "通过计划任务启动（内部使用）")
	modeFlag := flag.String("mode", "launcher", "运行模式: launcher|proxy|watchdog|uninstall")
	flag.Parse()

	// 检查 --scheduled 兼容模式
	isScheduled := *scheduledFlag
	for _, arg := range os.Args[1:] {
		if arg == "--scheduled" {
			isScheduled = true
			break
		}
	}

	switch *modeFlag {
	case "launcher":
		runLauncher(isScheduled)
	case "proxy":
		runProxy()
	case "watchdog":
		runWatchdog()
	case "uninstall":
		runUninstall()
	default:
		fmt.Printf("[ERROR] 未知模式: %s\n", *modeFlag)
		fmt.Println("用法: Mitmproxy定位伪造工具.exe [--scheduled] [-mode=launcher|proxy|watchdog|uninstall]")
		os.Exit(1)
	}
}