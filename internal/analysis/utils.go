package analysis

import (
	"LSPTracer/internal/model"
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// --- 公用辅助函数 ---

type AnalysisResult struct {
	Code     string
	DataFlow []string
}

// AnalyzeCallSite 分析调用点代码，尝试简单的变量回溯
func AnalyzeCallSite(path string, line int, targetFunc string) AnalysisResult {
	file, err := os.Open(path)
	if err != nil {
		return AnalysisResult{}
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if line >= len(lines) {
		return AnalysisResult{}
	}
	code := strings.TrimSpace(lines[line])
	var flows []string

	args := extractArgs(code)
	if args != "" && !isStrictConstant(args) {
		// 1. 尝试查找本地变量定义
		defLine := findDefinition(lines, line, args)

		if defLine != "" {
			defValue := extractRHS(defLine)
			if isStrictConstant(defValue) {
				flows = append(flows, fmt.Sprintf("🟢 Defined as Constant: `%s`", strings.TrimSpace(defValue)))
			} else {
				flows = append(flows, fmt.Sprintf("⚠️ Variable Definition: `%s`", strings.TrimSpace(defValue)))
			}
		} else {
			// 2. 如果没找到定义，检查是否为方法参数
			// (targetFunc 可能是 "download" 或 "download(String)")
			funcNameSimple := targetFunc
			if idx := strings.Index(targetFunc, "("); idx != -1 {
				funcNameSimple = targetFunc[:idx]
			}

			if isMethodParameter(lines, line, funcNameSimple, args) {
				flows = append(flows, fmt.Sprintf("⚠️ Variable Definition: Method Parameter `%s`", args))
			}
		}
	}

	return AnalysisResult{
		Code:     code,
		DataFlow: flows,
	}
}

func findDefinition(lines []string, currentLine int, varName string) string {
	start := currentLine - 1
	limit := currentLine - 50 // 扩大搜索范围
	if limit < 0 {
		limit = 0
	}
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\s*=`)

	for i := start; i >= limit; i-- {
		text := strings.TrimSpace(lines[i])

		// 忽略注释行
		if strings.HasPrefix(text, "//") || strings.HasPrefix(text, "*") || strings.HasPrefix(text, "/*") {
			continue
		}

		if pattern.MatchString(text) {
			return text
		}
	}
	return ""
}

// 检查变量是否为方法参数
func isMethodParameter(lines []string, currentLine int, startFuncName string, varName string) bool {
	// 向前搜索函数定义
	for i := currentLine; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])

		// 找到包含函数名和左括号的行 (public String download(String url))
		if strings.Contains(line, startFuncName) && strings.Contains(line, "(") {
			// 避免匹配到调用 (e.g. this.download(...)) - 简单 heuristic: 方法定义通常有修饰符或返回类型
			// 但这里简单判断：如果是调用，通常以 ; 结尾 (Java)
			if strings.HasSuffix(line, ";") {
				continue
			}

			// 检查参数列表里是否有 varName
			// 简单正则匹配 \bvarName\b
			matched, _ := regexp.MatchString(`\b`+regexp.QuoteMeta(varName)+`\b`, line)
			return matched
		}

		// 别找太远
		if currentLine-i > 100 {
			break
		}
	}
	return false
}

func extractRHS(code string) string {
	parts := strings.SplitN(code, "=", 2)
	if len(parts) == 2 {
		return strings.TrimSuffix(parts[1], ";")
	}
	return code
}

// 提取括号内的内容
func extractArgs(code string) string {
	start := strings.Index(code, "(")
	end := strings.LastIndex(code, ")")
	if start != -1 && end > start {
		return strings.TrimSpace(code[start+1 : end])
	}
	return ""
}

// 严格常量检测
func isStrictConstant(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	if isNumber(expr) || expr == "true" || expr == "false" || expr == "null" {
		return true
	}
	if strings.HasSuffix(expr, ".class") {
		return true
	}
	if !strings.Contains(expr, "\"") {
		return false
	}
	noStr := regexp.MustCompile(`"[^"]*"`).ReplaceAllString(expr, "")
	clean := strings.ReplaceAll(noStr, "+", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if len(clean) > 0 {
		return false
	}
	return true
}

func isNumber(s string) bool {
	match, _ := regexp.MatchString(`^-?\d+(\.\d+)?$`, s)
	return match
}

func hasVariableChar(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '$' {
			return true
		}
	}
	return false
}

func truncateString(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// IsTypeMismatch 使用启发式规则检查变量类型是否明显不匹配
func IsTypeMismatch(code string, rule model.SinkRule, lines []string, currentLine int) bool {
	// 1. 提取调用方法的变量名 例如: "out.write(...)" -> "out"
	idx := strings.Index(code, ".")
	if idx == -1 {
		return false
	}

	// 简单的倒序查找变量名
	sub := strings.TrimSpace(code[:idx])
	// 匹配最后一个单词
	reVar := regexp.MustCompile(`([a-zA-Z0-9_$]+)$`)
	loc := reVar.FindStringIndex(sub)
	if loc == nil {
		return false
	}
	varName := sub[loc[0]:loc[1]]

	// ✨ Strategy 0: Static Method Check (Generic) ✨
	// 如果规则标记为 IsStatic (如 Files.write, System.load)，则调用者必须匹配类名 (Full or Short)
	if rule.IsStatic {
		// 1. 获取规则的 ShortClassName (e.g., "Files")
		ruleShort := rule.ClassName
		if idx := strings.LastIndex(ruleShort, "."); idx != -1 {
			ruleShort = ruleShort[idx+1:]
		}

		// 2. 检查变量名是否等于 ShortClassName 或 FullClassName
		//    e.g. 调用 "Files.write" -> varName="Files". Match!
		//    e.g. 调用 "java.nio.file.Files.write" -> varName="java.nio.file.Files" (requires smarter parsing, but varName regex handles simple qualified names OK-ish, usually people use ShortName)
		//    Regex `([a-zA-Z0-9_$]+)$` currently gets only the last part.
		//    If user writes `java.nio.file.Files.write`, varName matches "Files".
		//    So we just check against ruleShort.

		if varName != ruleShort && varName != rule.ClassName {
			return true // Mismatch: 静态方法必须通过类名调用
		}
	}

	// 2. 查找变量定义行
	defLine := findDefinition(lines, currentLine, varName)
	if defLine == "" {
		return false
	}

	// 3. 提取变量类型
	// 常见: "BufferedOutputStream bos =" 或 "bos = new BufferedOutputStream"
	// 简单策略：查找 varName 前面的单词，或者 new 后面的单词
	var declaredType string

	// 策略A: 声明式 "Type var ="
	parts := strings.Fields(defLine)
	for i, p := range parts {
		// 移除可能的赋值符号或分号
		cleanP := strings.Trim(p, ";=")
		if cleanP == varName && i > 0 {
			prev := parts[i-1]
			// 排除 final, static 等修饰符 (简单排除常见的小写关键字)
			if !isKeyword(prev) {
				declaredType = prev
				break
			}
			// 如果前一个是修饰符，再往前找一个? 暂不处理太复杂的
		}
	}

	// 策略B: 赋值式 "var = new Type"
	if declaredType == "" {
		reNew := regexp.MustCompile(`new\s+([A-Z][a-zA-Z0-9_$]*)`)
		matches := reNew.FindStringSubmatch(defLine)
		if len(matches) > 1 {
			declaredType = matches[1]
		}
	}

	if declaredType == "" {
		return false
	}

	// 消除泛型 List<String> -> List
	if idx := strings.Index(declaredType, "<"); idx != -1 {
		declaredType = declaredType[:idx]
	}

	// 4. 执行互斥检查 (Conservative Veto)
	// 规则: Stream 与 Writer/Reader 互斥
	// 如果变量是 Stream 但规则要求 Writer/Reader -> 能够断定不匹配 (Sink Rule通常很具体)

	// 简化类名
	ruleShort := rule.ClassName
	if idx := strings.LastIndex(ruleShort, "."); idx != -1 {
		ruleShort = ruleShort[idx+1:]
	}

	declaredType = strings.TrimSpace(declaredType)

	isStream := strings.HasSuffix(declaredType, "Stream")
	isWriter := strings.HasSuffix(declaredType, "Writer") || strings.HasSuffix(declaredType, "Reader")

	ruleIsStream := strings.HasSuffix(ruleShort, "Stream")
	ruleIsWriter := strings.HasSuffix(ruleShort, "Writer") || strings.HasSuffix(ruleShort, "Reader")

	if isStream && ruleIsWriter {
		return true // 这是一个 Stream 对象，但规则找的是 Writer/Reader，肯定是误报
	}
	if isWriter && ruleIsStream {
		return true
	}

	return false
}

func isKeyword(s string) bool {
	keywords := []string{"final", "static", "private", "public", "protected", "volatile", "transient"}
	for _, k := range keywords {
		if s == k {
			return true
		}
	}
	return false
}
