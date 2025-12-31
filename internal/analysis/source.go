package analysis

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type CallAnalysis struct {
	Code     string
	DataFlow []string
	IsSafe   bool
}

var (
	// 简单的污点源特征
	TaintSources = []string{"request.getParameter", "request.getHeader", "System.in"}
)


func traceDefinition(filePath string, varName string, usageLine int) string {
	// 倒序读取前 50 行
	lines, _ := ReadLinesBefore(filePath, usageLine, 50)
	
	// 正则: varName \s* =
	reAssign := regexp.MustCompile(`(?:^|[\s;])` + regexp.QuoteMeta(varName) + `\s*=`)

	for i := len(lines) - 1; i >= 0; i-- {
		code := strings.TrimSpace(lines[i])
		if strings.HasPrefix(code, "//") { continue }

		if reAssign.MatchString(code) {
			parts := strings.Split(code, "=")
			if len(parts) > 1 {
				rhs := strings.TrimSuffix(strings.TrimSpace(strings.Join(parts[1:], "=")), ";")
				
				// 分析右值
				if strings.Contains(rhs, "\"") {
					return fmt.Sprintf("🟢 Defined as Constant: `%s`", rhs)
				}
				for _, src := range TaintSources {
					if strings.Contains(rhs, src) {
						return fmt.Sprintf("🚨 VULNERABILITY: Source `%s`", rhs)
					}
				}
				// 简单的函数调用识别
				if strings.Contains(rhs, "(") && strings.Contains(rhs, ")") {
					return fmt.Sprintf("🔄 Via Function: `%s`", rhs)
				}
				return fmt.Sprintf("⚠️ Assigned: `%s`", rhs)
			}
		}
	}
	return fmt.Sprintf("❓ Definition not found for '%s'", varName)
}

func isVar(s string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z_]\w*$`, s)
	return match
}

// 辅助函数：读取指定行
func ReadLine(path string, line int) (string, error) {
	f, err := os.Open(path)
	if err != nil { return "", err }
	defer f.Close()
	
	scanner := bufio.NewScanner(f)
	curr := 0
	for scanner.Scan() {
		if curr == line {
			return scanner.Text(), nil
		}
		curr++
	}
	return "", fmt.Errorf("EOF")
}

func ReadLinesBefore(path string, targetLine int, count int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()

	var result []string
	start := targetLine - count
	if start < 0 { start = 0 }

	scanner := bufio.NewScanner(f)
	curr := 0
	for scanner.Scan() {
		if curr >= start && curr < targetLine {
			result = append(result, scanner.Text())
		}
		curr++
	}
	return result, nil
}