package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"LSPTracer/internal/model"

	"github.com/fatih/color"
)

// Vulnerability 结构体
type Vulnerability struct {
	ID    int
	Steps []ReportStep
}

type ReportData struct {
	GeneratedAt string
	TotalChains int
	Vulns       []Vulnerability
}

type ReportStep struct {
	Index     int
	Type      string
	TypeClass string
	Func      string
	File      string
	Line      int
	Code      string
	FullCode  template.HTML
	Analysis  []string
}

// HTML 模板 (包含了你的 View Full Context 样式)
const htmlTemplateStr = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LSPTracer Scan Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1100px; margin: 0 auto; }
        
        .report-header { background: white; padding: 20px 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 30px; border-left: 5px solid #d32f2f; }
        .report-header h1 { margin: 0; color: #2c3e50; font-size: 24px; }
        .meta { color: #7f8c8d; font-size: 14px; margin-top: 5px; }

        .vuln-card { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 40px; overflow: hidden; }
        .vuln-title { background: #2c3e50; color: white; padding: 15px 20px; font-weight: bold; display: flex; justify-content: space-between; }
        .chain-body { padding: 20px; }

        .timeline { position: relative; padding-left: 20px; }
        .timeline::before { content: ''; position: absolute; left: 0; top: 10px; bottom: 0; width: 2px; background: #e0e0e0; }
        
        .step { position: relative; margin-bottom: 30px; padding-left: 25px; }
        .step::before { content: ''; position: absolute; left: -26px; top: 0; width: 14px; height: 14px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 0 2px #e0e0e0; z-index: 1; }
        
        .type-source::before { background: #d32f2f; box-shadow: 0 0 0 2px #d32f2f; }
        .type-step::before { background: #fbc02d; box-shadow: 0 0 0 2px #fbc02d; }
        .type-sink::before { background: #212121; box-shadow: 0 0 0 2px #212121; }

        .step-header { display: flex; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
        .tag { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 10px; color: white; }
        .tag-source { background: #d32f2f; }
        .tag-step { background: #f9a825; }
        .tag-sink { background: #212121; }
        
        .func-name { font-family: 'JetBrains Mono', Consolas, monospace; font-weight: bold; color: #000; font-size: 1.1em; }
        .file-loc { font-size: 13px; color: #7f8c8d; margin-left: auto; font-family: monospace; }

        .code-box { background: #fafafa; border: 1px solid #eee; border-radius: 4px; padding: 10px; margin-top: 5px; }
        .summary-code { font-family: 'JetBrains Mono', Consolas, monospace; font-size: 13px; color: #444; overflow-x: auto; white-space: pre-wrap; background: #fff; padding: 5px; border: 1px solid #eee; }
        
        .analysis-item { margin-top: 5px; font-size: 13px; color: #555; }

        .toggle-btn { background: none; border: none; color: #3498db; cursor: pointer; font-size: 12px; padding: 0; margin-top: 8px; text-decoration: underline; }
        .toggle-btn:hover { color: #2980b9; }

        .full-code-context { display: none; margin-top: 10px; background: #282c34; padding: 10px; border-radius: 4px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 12px; line-height: 1.6; color: #abb2bf; overflow-x: auto; }
        .code-line { display: block; white-space: pre; }
        .line-num { color: #5c6370; margin-right: 15px; user-select: none; display: inline-block; width: 35px; text-align: right; border-right: 1px solid #3e4451; padding-right: 5px;}
        
        .highlight-line { background-color: #3e4451; display: block; width: 100%; }
        .highlight-line .line-num { color: #e5c07b; font-weight: bold; }

        .s-kwd { color: #c678dd; font-weight: bold; } 
        .s-type { color: #e5c07b; } 
        .s-str { color: #98c379; }  
        .s-ann { color: #d19a66; }  
        .s-com { color: #7f848e; font-style: italic; } 
        .s-num { color: #d19a66; }  
        .s-func { color: #61afef; } 
    </style>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>🔥 LSPTracer Security Report</h1>
            <div class="meta">Generated at: {{.GeneratedAt}} | Total Chains Found: <strong>{{.TotalChains}}</strong></div>
        </div>

        {{range .Vulns}}
        {{ $vulnID := .ID }}
        <div class="vuln-card">
            <div class="vuln-title">
                <span>Vulnerability Chain #{{.ID}}</span>
                <span style="font-size: 0.8em; opacity: 0.8;">Depth: {{len .Steps}}</span>
            </div>
            <div class="chain-body">
                <div class="timeline">
                    {{range .Steps}}
                    <div class="step type-{{.TypeClass}}">
                        <div class="step-header">
                            <span class="tag tag-{{.TypeClass}}">{{.Type}}</span>
                            <span class="func-name">{{.Func}}</span>
                            <span class="file-loc">{{.File}}:{{.Line}}</span>
                        </div>
                        
                        <div class="code-box">
                            {{if .Code}}
                                <div class="summary-code">{{.Code}}</div>
                            {{end}}
                            
                            {{range .Analysis}}
                                <div class="analysis-item">{{.}}</div>
                            {{end}}

                            <button class="toggle-btn" onclick="toggleCode('code-{{$vulnID}}-{{.Index}}')">View Full Context</button>
                            
                            <div id="code-{{$vulnID}}-{{.Index}}" class="full-code-context">
                                {{.FullCode}}
                            </div>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
        </div>
        {{end}}

    </div>

    <script>
        function toggleCode(id) {
            var el = document.getElementById(id);
            if (el.style.display === "block") {
                el.style.display = "none";
            } else {
                el.style.display = "block";
            }
        }
    </script>
</body>
</html>
`

// GenerateHTML 生成 HTML 报告
func GenerateHTML(allChains [][]model.ChainStep, projectRoot string) {
	if len(allChains) == 0 {
		return
	}

	var vulns []Vulnerability

	for chainIdx, stack := range allChains {
		var steps []ReportStep
		chainLen := len(stack)

		for i := chainLen - 1; i >= 0; i-- {
			step := stack[i]

			stepType := "STEP"
			typeClass := "step"
			if i == chainLen-1 {
				stepType = "SOURCE"
				typeClass = "source"
			} else if i == 0 {
				stepType = "SINK"
				typeClass = "sink"
			}

			// ✨✨✨ 使用绝对路径读取代码 (step.File 现在是绝对路径) ✨✨✨
			fullCodeHTML := getSmartCodeContext(step.File, step.Line, step.Func)

			// ✨✨✨ 计算相对路径用于 HTML 展示 ✨✨✨
			displayPath := step.File
			if rel, err := filepath.Rel(projectRoot, step.File); err == nil {
				displayPath = rel
			}

			steps = append(steps, ReportStep{
				Index:     i,
				Type:      stepType,
				TypeClass: typeClass,
				Func:      step.Func,
				File:      displayPath, // 展示给用户看的是相对路径
				Line:      step.Line + 1,
				Code:      step.Code,
				FullCode:  template.HTML(fullCodeHTML),
				Analysis:  step.Analysis,
			})
		}

		vulns = append(vulns, Vulnerability{
			ID:    chainIdx + 1,
			Steps: steps,
		})
	}

	data := ReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		TotalChains: len(vulns),
		Vulns:       vulns,
	}

	t, err := template.New("report").Parse(htmlTemplateStr)
	if err != nil {
		color.Red("[-] Failed to generate report template: %v", err)
		return
	}

	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		color.Red("[-] Failed to create output directory: %v", err)
		return
	}
	fileName := fmt.Sprintf("report_%d.html", time.Now().Unix())
	f, err := os.Create(filepath.Join(outputDir, fileName))
	if err != nil {
		color.Red("[-] Failed to create output file: %v", err)
		return
	}
	defer f.Close()

	err = t.Execute(f, data)
	if err != nil {
		color.Red("[-] Failed to write report data: %v", err)
		return
	}

	absReportPath, _ := filepath.Abs(filepath.Join(outputDir, fileName))
	color.Green("[+] Report generated successfully: %s", absReportPath)
}

// -----------------------------------------------------------------------------
// 智能代码提取 (支持花括号平衡算法)
// -----------------------------------------------------------------------------

func getSmartCodeContext(path string, targetLine int, funcName string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		// 如果相对路径读不到，尝试报错信息
		return fmt.Sprintf("Error reading source file: %s", path)
	}

	lines := strings.Split(string(content), "\n")
	totalLines := len(lines)

	// 1. 尝试智能查找函数边界
	// Step A: Find the line where the function is defined (e.g., "public void foo(...)")
	defLine := findFunctionDefLine(lines, targetLine, funcName)
	startLine := -1
	endLine := -1

	if defLine != -1 {
		// Step B: Scan upwards for annotations (e.g. @RequestMapping)
		startLine = scanUpForAnnotations(lines, defLine)

		// Step C: Scan downwards for the closing brace, starting from the DEFINITION line
		// (Avoids confusing braces inside annotations)
		endLine = findFunctionEnd(lines, defLine)
	}

	// Double Check: Ensure the Found Range covers the Target Line
	if startLine != -1 && endLine != -1 {
		if targetLine < startLine || targetLine > endLine {
			// The found function definition is NOT enclosing the target line.
			startLine = -1
			endLine = -1
		}
	}

	// 2. 兜底策略：如果没找到，使用固定窗口
	if startLine == -1 || endLine == -1 {
		startLine = targetLine - 20
		if startLine < 0 {
			startLine = 0
		}
		endLine = targetLine + 20
		if endLine >= totalLines {
			endLine = totalLines - 1
		}
	} else {
		// 长度防御
		if endLine > totalLines-1 {
			endLine = totalLines - 1
		}
	}

	var sb strings.Builder
	for i := startLine; i <= endLine; i++ { // 注意这里是 <=
		if i >= totalLines {
			break
		}

		lineNum := i + 1
		rawCode := lines[i]

		// 3. 语法高亮
		highlightedCode := highlightJavaSyntax(rawCode)

		// 4. 包装 HTML
		cssClass := "code-line"
		if i == targetLine {
			cssClass += " highlight-line"
		}

		sb.WriteString(fmt.Sprintf("<span class='%s'><span class='line-num'>%d</span>%s</span>", cssClass, lineNum, highlightedCode))
	}
	return sb.String()
}

// 向上查找函数定义行 (不包含注解扫描，仅定位 public void xxx 部分)
func findFunctionDefLine(lines []string, targetIdx int, funcName string) int {
	// 如果 funcName 包含参数 (e.g. "query(String)"), 截取括号前的内容
	if idx := strings.Index(funcName, "("); idx != -1 {
		funcName = funcName[:idx]
	}

	// 使用正则进行精确的全词匹配 (Word Boundary)
	safePattern := regexp.QuoteMeta(funcName)
	pattern := fmt.Sprintf(`\b%s\b`, safePattern)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return -1
	}

	for i := targetIdx; i >= 0; i-- {
		rawLine := lines[i]
		line := strings.TrimSpace(rawLine)

		if len(line) == 0 {
			continue
		}

		// 1. 忽略注释行
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "/*") {
			continue
		}

		// 2. ✨✨✨ Mask Strings to avoid matching function names inside quotes (e.g. @RequestMapping("/call")) ✨✨✨
		maskedLine := maskStrings(line)

		// Check keywords on the MASKED line (safer)
		ignoredKeywords := []string{"return", "if", "else", "for", "while", "do", "switch", "case", "catch", "try", "throw", "new"}
		isKeyword := false
		for _, kw := range ignoredKeywords {
			// Check prefix on masked line to ensure we don't match "returnVal" as "return"
			// But maskedLine has replaced strings with spaces.
			// We can just check regex \bkeyword\b or HasPrefix with space check.
			if strings.HasPrefix(maskedLine, kw) {
				if len(maskedLine) == len(kw) || !isAlphaNum(maskedLine[len(kw)]) {
					isKeyword = true
					break
				}
			}
		}
		if isKeyword {
			continue
		}

		// 3. 快速过滤: 必须包含 "(" (Check in MASKED line to avoid "(" inside string)
		if !strings.Contains(maskedLine, "(") {
			continue
		}

		// 4. 正则查找位置 (在 MASKED line 上查找，避开字符串内的匹配)
		loc := re.FindStringIndex(maskedLine)
		if loc == nil {
			continue
		}
		idx := loc[0]

		// 5. heuristic: 如果函数名前面是点 (e.g. obj.method(...))
		if idx > 0 && maskedLine[idx-1] == '.' {
			continue
		}

		// 6. heuristic: 如果行尾是分号
		if strings.HasSuffix(strings.TrimSpace(maskedLine), ";") {
			continue
		}

		return i // Found the definition line!
	}
	return -1
}

// 辅助：将字符串内容屏蔽为空格，保持长度不变
func maskStrings(code string) string {
	var buf bytes.Buffer
	inString := false
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c == '"' {
			if i > 0 && code[i-1] == '\\' {
				// 转义引号，保留原样或替换为空格 (替换为空格更安全)
				buf.WriteByte(' ')
			} else {
				inString = !inString
				buf.WriteByte('"')
			}
		} else {
			if inString {
				buf.WriteByte(' ')
			} else {
				buf.WriteByte(c)
			}
		}
	}
	return buf.String()
}

func scanUpForAnnotations(lines []string, funcDefLine int) int {
	current := funcDefLine
	for i := funcDefLine - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			current = i
		} else {
			break
		}
	}
	return current
}

// 向下查找函数结尾
func findFunctionEnd(lines []string, startLine int) int {
	balance := 0
	foundFirstBrace := false

	for i := startLine; i < len(lines); i++ {
		line := lines[i]

		// 简单处理行注释：截断 // 后面
		cleanLine := line
		if idx := strings.Index(line, "//"); idx != -1 {
			// 为了简化，我们假设 // 就是注释 (不考虑 url http://...)
			cleanLine = line[:idx]
		}

		// 逐字符扫描
		inString := false
		for j := 0; j < len(cleanLine); j++ {
			char := cleanLine[j]

			// 处理转义
			if char == '\\' && j+1 < len(cleanLine) {
				j++
				continue
			}

			// 处理字符串状态
			if char == '"' {
				inString = !inString
				continue
			}

			if inString {
				continue
			}

			// 处理花括号
			if char == '{' {
				balance++
				foundFirstBrace = true
			} else if char == '}' {
				balance--
			}
		}

		// 如果已经开始了这个函数块，并且平衡归零，说明函数结束了
		if foundFirstBrace && balance == 0 {
			return i
		}

		// 防止异常情况一直跑到底
		if i-startLine > 500 { // 限制最大 500 行
			return i
		}
	}

	// 如果没找到匹配的结尾，默认显示 20 行
	return startLine + 20
}

// highlightJavaSyntax (保持不变)
func highlightJavaSyntax(code string) string {
	code = strings.ReplaceAll(code, "&", "&amp;")
	code = strings.ReplaceAll(code, "<", "&lt;")
	code = strings.ReplaceAll(code, ">", "&gt;")
	return fastLexer(code)
}

// fastLexer (保持不变)
func fastLexer(code string) string {
	var buf bytes.Buffer
	n := len(code)
	i := 0

	isAlpha := func(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' }
	isNum := func(c byte) bool { return c >= '0' && c <= '9' }

	keywords := map[string]bool{
		"public": true, "private": true, "protected": true, "class": true, "interface": true, "enum": true,
		"return": true, "if": true, "else": true, "for": true, "while": true, "do": true, "new": true,
		"static": true, "final": true, "void": true, "import": true, "package": true, "try": true, "catch": true,
		"throws": true, "throw": true, "extends": true, "implements": true, "this": true, "super": true,
	}

	for i < n {
		c := code[i]

		if c == '"' {
			start := i
			i++
			for i < n && code[i] != '"' {
				if code[i] == '\\' {
					i++
				}
				i++
			}
			if i < n {
				i++
			}
			buf.WriteString(`<span class="s-str">`)
			buf.WriteString(code[start:i])
			buf.WriteString(`</span>`)
			continue
		}

		if c == '/' && i+1 < n && code[i+1] == '/' {
			buf.WriteString(`<span class="s-com">`)
			buf.WriteString(code[i:])
			buf.WriteString(`</span>`)
			break
		}

		if c == '@' {
			start := i
			i++
			for i < n && (isAlpha(code[i]) || isNum(code[i])) {
				i++
			}
			buf.WriteString(`<span class="s-ann">`)
			buf.WriteString(code[start:i])
			buf.WriteString(`</span>`)
			continue
		}

		if isAlpha(c) {
			start := i
			for i < n && (isAlpha(code[i]) || isNum(code[i])) {
				i++
			}
			word := code[start:i]

			isFuncCall := false
			j := i
			for j < n && code[j] == ' ' {
				j++
			}
			if j < n && code[j] == '(' {
				isFuncCall = true
			}

			if keywords[word] {
				buf.WriteString(`<span class="s-kwd">`)
				buf.WriteString(word)
				buf.WriteString(`</span>`)
			} else if isFuncCall {
				buf.WriteString(`<span class="s-func">`)
				buf.WriteString(word)
				buf.WriteString(`</span>`)
			} else if len(word) > 0 && word[0] >= 'A' && word[0] <= 'Z' {
				buf.WriteString(`<span class="s-type">`)
				buf.WriteString(word)
				buf.WriteString(`</span>`)
			} else {
				buf.WriteString(word)
			}
			continue
		}

		buf.WriteByte(c)
		i++
	}

	return buf.String()
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}
