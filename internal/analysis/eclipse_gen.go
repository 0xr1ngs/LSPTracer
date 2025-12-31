package analysis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
)

// GenerateEclipseConfig 自动生成 .project 和 .classpath 文件
// 这里的核心思路是：找到所有的源码目录，把它们加入到 .classpath 中
// 这样 JDT.LS 就会直接读取源码，而不去解析 pom.xml
func GenerateEclipseConfig(projectRoot string) error {
	projectFile := filepath.Join(projectRoot, ".project")
	classpathFile := filepath.Join(projectRoot, ".classpath")

	// 1. 扫描所有的 source root (src/main/java 等)
	srcDirs, err := scanSourceDirs(projectRoot)
	if err != nil {
		return err
	}

	if len(srcDirs) == 0 {
		// 如果找不到标准目录，就把根目录当作源码目录（兜底）
		srcDirs = append(srcDirs, "") 
	}

	// 2. 生成 .project 内容 (注意：这里不包含 maven nature)
	projectName := filepath.Base(projectRoot)
	projectContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<projectDescription>
	<name>%s</name>
	<comment></comment>
	<projects>
	</projects>
	<buildSpec>
		<buildCommand>
			<name>org.eclipse.jdt.core.javabuilder</name>
			<arguments>
			</arguments>
		</buildCommand>
	</buildSpec>
	<natures>
		<nature>org.eclipse.jdt.core.javanature</nature>
	</natures>
</projectDescription>
`, projectName)

	// 3. 生成 .classpath 内容
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(`<classpath>` + "\n")
	
	// 添加所有扫描到的源码目录
	for _, src := range srcDirs {
		// 转换为相对路径
		rel, _ := filepath.Rel(projectRoot, src)
		if rel == "." { rel = "" }
		// kind="src" 告诉 JDTLS 这里面是源码，建立索引！
		sb.WriteString(fmt.Sprintf(`	<classpathentry kind="src" path="%s"/>` + "\n", rel))
	}

	// 添加基本的 JRE 容器 (让 String, System 等基础类能识别)
	sb.WriteString(`	<classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER/org.eclipse.jdt.internal.debug.ui.launcher.StandardVMType/JavaSE-1.8"/>` + "\n")
	sb.WriteString(`	<classpathentry kind="output" path="bin"/>` + "\n")
	sb.WriteString(`</classpath>`)

	// 4. 写入文件
	if err := os.WriteFile(projectFile, []byte(projectContent), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(classpathFile, []byte(sb.String()), 0644); err != nil {
		return err
	}

	color.Green("[+] Generated lightweight Eclipse config (Source Roots: %d)", len(srcDirs))
	return nil
}

// 递归查找所有包含 .java 文件的目录，并尝试定位到 source root
func scanSourceDirs(root string) ([]string, error) {
	var srcDirs []string
	seen := make(map[string]bool)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		
		// 忽略隐藏目录和构建目录
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "target" || info.Name() == "build" || info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasSuffix(info.Name(), ".java") {
			// ✨✨✨ 智能倒推逻辑 ✨✨✨
			detectedRoot := detectSourceRootFromPackage(path)
			if detectedRoot != "" {
				if !seen[detectedRoot] {
					srcDirs = append(srcDirs, detectedRoot)
					seen[detectedRoot] = true
				}
				// 一旦在这个目录下找到了一个合法的 java 文件并确定了 root，
				// 这个 root 下的其他文件就不需要再扫描了，避免重复 IO，但 Walk 无法跳过同级文件，只能继续
			}
		}
		return nil
	})
	
	// 如果没找到任何包结构，但有 java 文件，把根目录算进去
	if len(srcDirs) == 0 {
		hasJava := false
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if strings.HasSuffix(info.Name(), ".java") {
				hasJava = true
				return filepath.SkipDir // 只要找到一个就行
			}
			return nil
		})
		if hasJava {
			srcDirs = append(srcDirs, root)
		}
	}
	
	return srcDirs, err
}

// 读取 Java 文件头，提取 package，计算源码根
func detectSourceRootFromPackage(javaFilePath string) string {
	f, err := os.Open(javaFilePath)
	if err != nil { return "" }
	defer f.Close()

	// 只读前 20 行，通常 package 声明都在最前面
	scanner := bufio.NewScanner(f)
	packagePath := ""
	
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 20 { break }
		
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "package ") && strings.HasSuffix(line, ";") {
			// 提取包名: package com.example.util; -> com.example.util
			rawPkg := strings.TrimSuffix(strings.TrimPrefix(line, "package "), ";")
			// 转换为路径: com/example/util
			packagePath = strings.ReplaceAll(rawPkg, ".", string(os.PathSeparator))
			break
		}
	}

	// 如果没有 package 声明 (Default Package)，那么文件所在目录就是 Source Root
	if packagePath == "" {
		return filepath.Dir(javaFilePath)
	}

	// 倒推逻辑
	// 假设文件路径: /A/B/src/com/demo/Test.java
	// 包路径:       com/demo
	// 我们期望得到: /A/B/src
	
	absPath, _ := filepath.Abs(javaFilePath)
	dir := filepath.Dir(absPath) // /A/B/src/com/demo
	
	if strings.HasSuffix(dir, packagePath) {
		// 截取
		root := strings.TrimSuffix(dir, packagePath)
		// 去掉末尾可能残留的路径分隔符
		root = strings.TrimSuffix(root, string(os.PathSeparator))
		return root
	}
	
	return ""
}