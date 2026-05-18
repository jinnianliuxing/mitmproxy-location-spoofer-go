// proxy.go - Pure Go MITM Proxy（仅定位伪造，无签名捕获）
package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/elazarl/goproxy"
)

//go:embed mitmproxy-ca-cert.pem
var embeddedCACertPEM []byte

//go:embed mitmproxy-ca.pem
var embeddedCAKeyPEM []byte

//go:embed mitmproxy-ca-cert.cer
var embeddedCACertCER []byte

// writeFileForAllUsers 写入文件并确保所有用户可访问（避免管理员写入后普通进程无法读取）
func writeFileForAllUsers(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	// Windows 下修改 DACL，添加 Everyone 读取权限
	modadvapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return nil
	}
	procSetEntriesInAclW, err := modadvapi32.FindProc("SetEntriesInAclW")
	if err != nil {
		return nil
	}
	procSetNamedSecurityInfoW, err := modadvapi32.FindProc("SetNamedSecurityInfoW")
	if err != nil {
		return nil
	}

	pathPtr, _ := syscall.UTF16PtrFromString(path)

	const (
		SE_FILE_OBJECT              = 1
		DACL_SECURITY_INFORMATION   = 4
		GRANT_ACCESS                = 1
		FILE_GENERIC_READ           = 0x80000000 | 0x40000000 | 0x20000000 | 0x10000000 | 0x08000000
		TRUSTEE_IS_SID              = 2
		TRUSTEE_IS_WELL_KNOWN_GROUP = 5
	)

	type TRUSTEE struct {
		pMultipleTrustee *byte
		MultipleTrustee  uint32
		TrusteeForm      uint32
		TrusteeType      uint32
		ptstrName        *uint16
	}
	type EXPLICIT_ACCESS struct {
		grfAccessPermissions uint32
		grfAccessMode        uint32
		grfInheritance       uint32
		Trustee              TRUSTEE
	}

	everyoneSIDStr, _ := syscall.UTF16PtrFromString("S-1-1-0")
	trustee := TRUSTEE{
		TrusteeForm: TRUSTEE_IS_SID,
		TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
		ptstrName:   everyoneSIDStr,
	}
	ea := EXPLICIT_ACCESS{
		grfAccessPermissions: FILE_GENERIC_READ,
		grfAccessMode:        GRANT_ACCESS,
		grfInheritance:       0,
		Trustee:              trustee,
	}

	var newAcl uintptr
	ret, _, _ := procSetEntriesInAclW.Call(
		1,
		uintptr(unsafe.Pointer(&ea)),
		0,
		uintptr(unsafe.Pointer(&newAcl)),
	)
	if ret != 0 {
		return nil
	}
	defer syscall.NewLazyDLL("advapi32.dll").NewProc("LocalFree").Call(newAcl)

	procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		0,
		0,
		newAcl,
		0,
	)
	return nil
}

const (
	proxyHost    = "127.0.0.1"
	proxyPort    = 8888
	targetQQMap  = "apis.map.qq.com"
	targetSimple = "simp.csuft.edu.cn"
)

var locations = map[int]Location{
	1: {Lat: 28.120000, Lng: 113.0262, Name: "校外"},
	2: {Lat: 28.130000, Lng: 112.987956, Name: "校内(宿舍)"},
	3: {Lat: 666.000000, Lng: 666.000000, Name: "自定义"},
}

var selectedMode = 2

type Location struct {
	Lat  float64 `json:"lat"`
	Lng  float64 `json:"lng"`
	Name string
}

// 主机名匹配 - 兼容 CONNECT 请求中的 :443 端口号
func hostMatchCond(targetHost string) goproxy.ReqCondition {
	return goproxy.ReqConditionFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) bool {
		hostOnly := r.URL.Host
		if hostOnly == "" {
			hostOnly = r.Host
		}
		if i := strings.LastIndex(hostOnly, ":"); i > 0 {
			hostOnly = hostOnly[:i]
		}
		return hostOnly == targetHost
	})
}

func isTargetHost(host string) bool {
	hostOnly := host
	if i := strings.LastIndex(host, ":"); i > 0 {
		hostOnly = host[:i]
	}
	return hostOnly == targetQQMap || hostOnly == targetSimple
}

func initEmbeddedCA() {
	ca, err := tls.X509KeyPair(embeddedCACertPEM, embeddedCAKeyPEM)
	if err == nil {
		goproxy.GoproxyCa = ca
		fmt.Println("[OK] 已加载内嵌 CA 证书")
	} else {
		fmt.Printf("[WARN] CA加载失败: %v\n", err)
	}
}

// ====== 代理关闭标记 ======
var proxyExiting bool

func runProxy() {
	fmt.Println("=" + repeat("=", 60))
	fmt.Println("   Mitmproxy 定位伪造工具 - Pure Go")
	fmt.Printf("   代理: %s:%d\n", proxyHost, proxyPort)
	fmt.Printf("   位置: %s (%.6f, %.6f)\n", locations[selectedMode].Name, locations[selectedMode].Lat, locations[selectedMode].Lng)
	fmt.Println("=" + repeat("=", 60))
	fmt.Println()

	fmt.Println("[*] 启用系统代理...")
	if !setProxy(true, fmt.Sprintf("%s:%d", proxyHost, proxyPort)) {
		fmt.Println("[ERROR] 无法启用系统代理")
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}
	fmt.Println("[OK] 系统代理已启用")
	fmt.Println()

	initEmbeddedCA()
	ensureCAConfigured()

	// ====== 构建 goproxy ======
	ps := goproxy.NewProxyHttpServer()

	// 对腾讯地图和 simp.csuft.edu.cn 启用 HTTPS MITM
	ps.OnRequest(hostMatchCond(targetQQMap)).HandleConnect(goproxy.AlwaysMitm)
	ps.OnRequest(hostMatchCond(targetSimple)).HandleConnect(goproxy.AlwaysMitm)

	// 请求日志 + dormSignTask API 监听提示
	var reqCount int64
	var dormSignDetected bool
	ps.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		reqCount++
		if isTargetHost(r.Host) || isTargetHost(r.URL.Host) {
			host := r.URL.Host
			if host == "" {
				host = r.Host
			}
			// 判断是否是 simple 目标主机
			hostOnly := host
			if i := strings.LastIndex(host, ":"); i > 0 {
				hostOnly = host[:i]
			}
			
			// 添加对 dormSignTask API 的日志输出 - 简洁格式
			if strings.Contains(r.URL.Path, "/api/flySource-yxgl/dormSignTask/") {
				if !dormSignDetected {
					dormSignDetected = true
					fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
					fmt.Println("  ✅ 持续监听中 — 代理已成功拦截数据流量")
					fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
				}
				fmt.Printf("[#%d] [DORMSIGN] %s %s\n", reqCount, r.Method, r.URL.Path)
			} else if hostOnly == targetSimple {
				fmt.Printf("[#%d] [simple] %s %s\n", reqCount, r.Method, r.URL.String())
			} else {
				fmt.Printf("[#%d] %s %s %s\n", reqCount, r.Method, host, r.URL.Path)
			}
		}
		return r, nil
	})

	// 响应处理：定位伪造 + simple API 日志
	ps.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}
		host := ctx.Req.URL.Host
		if host == "" {
			host = ctx.Req.Host
		}

		if isTargetHost(host) {
			hostOnly := host
			if i := strings.LastIndex(host, ":"); i > 0 {
				hostOnly = host[:i]
			}

			// 如果是对 simple 主机的响应，打印简洁日志（仅状态码）
			if hostOnly == targetSimple {
				fmt.Printf("  <- %d\n", resp.StatusCode)
				return resp
			}

			fmt.Printf("  <- %d\n", resp.StatusCode)

			if strings.Contains(ctx.Req.URL.Path, "/ws/coord/v1/translate") {
				location := locations[selectedMode]
				fmt.Println()
				fmt.Println("=" + repeat("=", 60))
				fmt.Println("[INFO] 拦截到定位请求!")
				fmt.Printf("   原始坐标: %s\n", ctx.Req.URL.Query().Get("locations"))
				fmt.Printf("   伪造位置: %s (%.6f, %.6f)\n", location.Name, location.Lat, location.Lng)
				fmt.Println("   [SUCCESS] 已伪造定位成功！")
				fmt.Println("=" + repeat("=", 60))

				fakeResp := map[string]interface{}{
					"status":     0,
					"message":    "query ok",
					"request_id": fmt.Sprintf("go_%s", time.Now().Format("150405")),
					"locations":  []map[string]float64{{"lat": location.Lat, "lng": location.Lng}},
				}
				bodyBytes, _ := json.Marshal(fakeResp)
				resp.StatusCode = 200
				resp.Header.Set("Content-Type", "application/json; charset=utf-8")
				resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				resp.ContentLength = int64(len(bodyBytes))
			}
		}
		return resp
	})

	// ====== 启动服务器 ======
	addr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("[ERROR] 端口 %d 被占用: %v\n", proxyPort, err)
		cleanupProxy()
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}

	fmt.Println("=" + repeat("=", 60))
	fmt.Println("   [INFO] 代理已启动，等待请求...")
	fmt.Println("=" + repeat("=", 60))
	fmt.Println()
	fmt.Println("提示: 直接关闭窗口停止代理")
	fmt.Println()
	fmt.Printf("[OK] 监听 %s:%d\n\n", proxyHost, proxyPort)

	// 注意: 微信小程序由启动器(launcher)负责打开，代理内部不再自动调用
	// openWechatMiniprogram()

	server := &http.Server{Addr: addr, Handler: ps, IdleTimeout: 5 * time.Second}

	// ★ Ctrl+C/关闭窗口 → 单一路径退出
	// 信号 goroutine 只做一件事：收到信号 → 清理代理 → 关闭服务器
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		proxyExiting = true
		cleanupProxy()
		server.Close() // 立即中断 server.Serve()，程序秒退
	}()

	// 启动服务器（阻塞）
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("[ERROR] 服务器错误: %v\n", err)
	}

	// 确保最终清理
	cleanupProxy()
}

// ====== CA 证书 ======

func ensureCAConfigured() {
	if checkCertificateInstalled() {
		fmt.Println("[OK] 证书已安装")
		return
	}
	fmt.Println("[*] 从嵌入数据安装证书...")
	installCertificateFromEmbedded()
	fmt.Println()
}

func installCertificateFromEmbedded() bool {
	homeDir, _ := os.UserHomeDir()
	userMitmproxy := filepath.Join(homeDir, ".mitmproxy")
	os.MkdirAll(userMitmproxy, 0755)
	cerPath := filepath.Join(userMitmproxy, "mitmproxy-ca-cert.cer")
	writeFileForAllUsers(cerPath, embeddedCACertCER)
	writeFileForAllUsers(filepath.Join(userMitmproxy, "mitmproxy-ca-cert.pem"), embeddedCACertPEM)
	writeFileForAllUsers(filepath.Join(userMitmproxy, "mitmproxy-ca.pem"), embeddedCAKeyPEM)

	for attempt := 1; attempt <= 3; attempt++ {
		cmd := createCommand("certutil", "-addstore", "-user", "Root", cerPath)
		output, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(output), "成功") {
			fmt.Println("[OK] 证书安装成功")
			return true
		}
		if attempt < 3 {
			time.Sleep(1 * time.Second)
		}
	}
	return false
}

// ====== 代理清理 ======

func cleanupProxy() {
	setProxy(false, "")
}
