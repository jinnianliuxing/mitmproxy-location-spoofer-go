// uninstall.go - 卸载模块（Go 版，替代 uninstall_cert.py）
// 删除计划任务 + 卸载 mitmproxy 证书
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const uninstallTaskName = "MitmproxyLocationSpoofer_Elevate"

// 删除计划任务
func deleteScheduledTask() bool {
	fmt.Println("=" + repeat("=", 53))
	fmt.Println("  卸载计划任务")
	fmt.Println("=" + repeat("=", 53))
	fmt.Println()

	// 先检查任务是否存在
	checkCmd := exec.Command("schtasks", "/query", "/tn", uninstallTaskName)
	checkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := checkCmd.Run(); err != nil {
		fmt.Println("[INFO] 计划任务不存在，无需删除")
		return true
	}

	fmt.Printf("[*] 检测到计划任务 '%s' 存在\n", uninstallTaskName)
	fmt.Println("[*] 正在删除计划任务...")

	delCmd := exec.Command("schtasks", "/delete", "/tn", uninstallTaskName, "/f")
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := delCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 删除计划任务失败: %s\n", string(output))
		return false
	}

	fmt.Println("[OK] 计划任务已成功删除")
	return true
}

// 卸载证书
func uninstallCertificate() bool {
	fmt.Println("=" + repeat("=", 53))
	fmt.Println("  卸载 mitmproxy 证书（当前用户）")
	fmt.Println("=" + repeat("=", 53))
	fmt.Println()
	fmt.Println("正在从「当前用户」受信任的根证书中移除 mitmproxy 证书...")
	fmt.Println("如果弹出系统安全提示，请点击「是」以确认删除。")
	fmt.Println()

	cmd := exec.Command("certutil", "-delstore", "-user", "Root", "mitmproxy")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // certutil 在用户取消时也会返回非零，忽略错误

	fmt.Println()
	fmt.Println("[OK] 证书卸载操作已提交")
	return true
}

// 卸载主函数
func runUninstall() {
	// 检查是否以管理员身份运行
	if !isAdmin() {
		fmt.Println("=" + repeat("=", 53))
		fmt.Println("  Mitmproxy 清理工具")
		fmt.Println("=" + repeat("=", 53))
		fmt.Println()
		fmt.Println("[*] 检测到需要管理员权限")
		fmt.Println("[*] 正在请求管理员权限...")
		fmt.Println()

		runAsAdminAndExit()

		fmt.Println("[ERROR] 未能获取管理员权限，程序退出")
		fmt.Print("按任意键退出...")
		fmt.Scanln()
		os.Exit(1)
	}

	// 以下是管理员权限下的执行流程
	fmt.Println()
	fmt.Println("开始清理前置安装设置...")
	fmt.Println()

	// 第一步：删除计划任务
	taskResult := deleteScheduledTask()
	fmt.Println()

	// 第二步：卸载证书
	certResult := uninstallCertificate()
	fmt.Println()

	// 总结
	fmt.Println("=" + repeat("=", 53))
	fmt.Println("  清理完成")
	fmt.Println("=" + repeat("=", 53))
	if taskResult && certResult {
		fmt.Println("[OK] 所有清理操作均已完成")
	} else {
		if !taskResult {
			fmt.Println("[WARN] 计划任务清理可能未成功")
		}
		if !certResult {
			fmt.Println("[WARN] 证书卸载可能未成功")
		}
	}

	fmt.Println()
	fmt.Println("请按任意键退出...")
	fmt.Scanln()
	os.Exit(0)
}