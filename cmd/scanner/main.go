package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"LSPTracer/internal/analysis"
	"LSPTracer/internal/env"
	"LSPTracer/internal/lang"
	"LSPTracer/internal/lsp"
	"LSPTracer/internal/model"
	"LSPTracer/internal/report"

	"github.com/fatih/color"
)

// 定义命令行参数
var (
	argProject   = flag.String("project", "", "Path to the project root directory")
	argFile      = flag.String("file", "", "(Optional) Target file path with line number (e.g., src/Main.java:42). If empty, auto-scan mode is enabled.")
	argJdtlsHome = flag.String("jdtls", "", "Path to JDT.LS directory. If empty, it will be auto-downloaded.")
	argRules     = flag.String("rules", "", "(Optional) Path to external rules.yaml file.")
	argStrict    = flag.Bool("strict", false, "Enable strict source validation (only report chains starting at framework entry points)")
)

// 自动读取文件指定行的代码
func GetLineContent(path string, lineNum int) string {
	file, err := os.Open(path)
	if err != nil {
		return "Error reading code"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentLine := 0
	for scanner.Scan() {
		currentLine++
		if currentLine == lineNum {
			return strings.TrimSpace(scanner.Text())
		}
	}
	return "Line not found"
}

// 智能探测 Workspace Root (贪婪模式：向上查找最顶层的父工程)
func SmartWorkspaceFinder(targetFileAbs string) string {
	dir := filepath.Dir(targetFileAbs)
	var lastValidRoot string

	// 最多向上找 20 层
	for i := 0; i < 20; i++ {
		// 如果当前目录有构建文件
		if hasBuildFile(dir) {
			lastValidRoot = dir
		}

		// 继续向上找，不要停
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		} // 到达系统根目录 / 或 C:\
		dir = parent
	}

	// 如果找到了某一层有 pom，返回最上面那一层
	if lastValidRoot != "" {
		return lastValidRoot
	}

	// 如果完全没找到 pom，就返回文件所在目录的上一级作为兜底
	return filepath.Dir(targetFileAbs)
}

func hasBuildFile(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "pom.xml")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "build.gradle")); err == nil {
		return true
	}
	return false
}

// 强力清理：清除 JDT.LS 缓存以及项目下的 IDE 配置文件
// 确保每次启动都是干净的环境，强制 JDT.LS 读取我们新生成的配置
func ForceClean(root string) {
	// 1. 清理 JDT.LS 的数据缓存
	cacheDir := ".jdtls_data_cache"
	if _, err := os.Stat(cacheDir); err == nil {
		os.RemoveAll(cacheDir)
	}

	// 2. 清理项目目录下的 Eclipse 配置文件 (.project, .classpath)
	filesToDelete := []string{".project", ".classpath", ".factorypath"}
	for _, f := range filesToDelete {
		path := filepath.Join(root, f)
		if _, err := os.Stat(path); err == nil {
			os.Remove(path)
		}
	}

	// 3. 清理 .settings 目录
	settingsDir := filepath.Join(root, ".settings")
	if _, err := os.Stat(settingsDir); err == nil {
		os.RemoveAll(settingsDir)
	}
}

func main() {
	// 1. 强制清理 JDT.LS 缓存 (启动前先清理一次，防止读取旧索引)
	if _, err := os.Stat(".jdtls_data_cache"); err == nil {
		os.RemoveAll(".jdtls_data_cache")
	}

	// 2. 解析命令行
	flag.Parse()

	if *argProject == "" {
		log.Fatal("Please provide -project argument.\nExample: -project ./mall")
	}

	// 判断模式：是否为全自动扫描
	autoScanMode := false
	if *argFile == "" {
		autoScanMode = true
	}

	// 3. 环境自动准备
	var lombokPath string
	autoJdtls, autoLombok, err := env.EnsureEnv()
	if err != nil {
		log.Printf("[!] Environment setup warning: %v", err)
	}

	finalJdtlsHome := *argJdtlsHome
	if finalJdtlsHome == "" {
		finalJdtlsHome = autoJdtls
		if finalJdtlsHome != "" {
			color.Green("[*] Using auto-installed JDT.LS: %s", finalJdtlsHome)
		}
	}

	lombokPath = autoLombok

	if finalJdtlsHome == "" {
		log.Fatal("❌ JDT.LS not found. Please specify -jdtls or check network for auto-download.")
	}

	// 4. 处理路径 (Project Root)
	absProjectRoot, _ := filepath.Abs(*argProject)

	// 确定启动锚点文件 (Anchor File) 和 目标文件/行号
	var anchorFile string
	var targetLine int

	if autoScanMode {
		color.Cyan("[*] Auto-Scan Mode Enabled. Searching for anchor file...")
		// 自动寻找第一个 .java 文件作为 LSP 启动锚点
		filepath.Walk(absProjectRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Skip hidden dirs (like .mvn, .git, .idea) and build/target dirs
				if strings.HasPrefix(info.Name(), ".") || info.Name() == "target" || info.Name() == "build" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(info.Name(), ".java") {
				anchorFile = path
				return filepath.SkipDir // 找到一个就行
			}
			return nil
		})
		if anchorFile == "" {
			log.Fatal("[-] No .java files found in the project. Cannot start analysis.")
		}
	} else {
		// 解析 file:line 格式
		lastColon := strings.LastIndex(*argFile, ":")
		if lastColon == -1 {
			log.Fatal("Invalid file format. Please use 'path/to/file:line' (e.g., Main.java:42)")
		}

		rawFilePath := (*argFile)[:lastColon]
		lineStr := (*argFile)[lastColon+1:]

		var err error
		targetLine, err = strconv.Atoi(lineStr)
		if err != nil || targetLine <= 0 {
			log.Fatalf("Invalid line number: %s", lineStr)
		}

		if filepath.IsAbs(rawFilePath) {
			anchorFile = rawFilePath
		} else {
			anchorFile = filepath.Join(absProjectRoot, rawFilePath)
		}
	}

	// 5. 探测工作区根目录并清理配置
	realWorkspaceRoot := SmartWorkspaceFinder(anchorFile)
	color.Blue("[*] Smart Workspace Detected: %s", realWorkspaceRoot)

	ForceClean(realWorkspaceRoot)

	// ✨✨✨ 生成欺骗性 Eclipse 配置 ✨✨✨
	if err := analysis.GenerateEclipseConfig(realWorkspaceRoot); err != nil {
		color.Red("[-] Failed to generate Eclipse config: %v", err)
	}

	// 6. 构建命令 & 启动
	javaLang := lang.JavaConfig{
		JdtlsHome:  finalJdtlsHome,
		JavaExec:   "java",
		LombokPath: lombokPath,
	}
	cmd, err := javaLang.BuildCmd()
	if err != nil {
		log.Fatal(err)
	}

	client, err := lsp.NewClient(cmd)
	if err != nil {
		log.Fatalf("Failed to start LSP: %v", err)
	}
	defer client.Close()

	// 7. 启动追踪器
	tracer := analysis.NewTracer(client, realWorkspaceRoot)
	tracer.StrictMode = *argStrict
	tracer.Start(anchorFile) // 发送 didOpen 信号激活 LSP

	// 8. 根据模式执行扫描
	if autoScanMode {
		// ✨✨✨ 全自动扫描模式 ✨✨✨

		// 加载规则优先级: 1. 命令行参数 2. 当前目录 rules.yaml 3. 内置默认
		var rules []model.SinkRule
		var err error

		rulePath := *argRules
		if rulePath == "" {
			// 尝试默认文件名
			if _, err := os.Stat("rules.yaml"); err == nil {
				rulePath = "rules.yaml"
			}
		}

		if rulePath != "" {
			color.Cyan("[*] Loading rules from: %s", rulePath)
			rules, err = model.LoadRulesFromFile(rulePath)
			if err != nil {
				log.Fatalf("[-] Failed to load rules from %s: %v", rulePath, err)
			}
		} else {
			color.Cyan("[*] Using built-in default rules.")
			rules = model.GetBuiltinRules()
		}

		color.Blue("[*] Loaded %d rules.", len(rules))

		tracer.ScanAndTrace(rules)
	} else {
		// ✨✨✨ 单点狙击模式 ✨✨✨
		color.Cyan("[*] Analyzing Sink at Line %d", targetLine)

		targetLineIndex := targetLine - 1
		funcName, funcLine, funcCol := tracer.GetEnclosingFunction(lsp.ToUri(anchorFile), targetLineIndex)

		if funcName != "" {
			color.Green("[+] Hit Initial Function: %s (Line:%d)", funcName, funcLine+1)

			realCode := GetLineContent(anchorFile, targetLine)

			firstStep := model.ChainStep{
				File: anchorFile,
				Line: targetLineIndex,
				Func: funcName,
				Code: realCode,
			}

			tracer.TraceChain(anchorFile, funcLine, funcCol, []model.ChainStep{firstStep})
		} else {
			color.Red("[-] Could not find function context. Is the line number correct?")
		}
	}

	// 9. 生成报告
	if len(tracer.Results) > 0 {
		// ✨✨✨ 传入 realWorkspaceRoot (项目根目录) ✨✨✨
		report.GenerateHTML(tracer.Results, realWorkspaceRoot)
	} else {
		fmt.Println()
		color.Yellow("[*] No vulnerability chains found.")
	}
}
