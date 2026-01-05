package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LSPTracer/internal/lsp"
	"LSPTracer/internal/model"

	"github.com/fatih/color"
)

type Tracer struct {
	Client        *lsp.Client
	ProjectRoot   string
	SymbolCache   map[string][]lsp.DocumentSymbol
	Visited       map[string]bool
	ReportedEntry map[string]bool
	Results       [][]model.ChainStep
	StrictMode    bool
}

func NewTracer(client *lsp.Client, root string) *Tracer {
	return &Tracer{
		Client:        client,
		ProjectRoot:   root,
		SymbolCache:   make(map[string][]lsp.DocumentSymbol),
		Visited:       make(map[string]bool),
		ReportedEntry: make(map[string]bool),
		Results:       make([][]model.ChainStep, 0),
		StrictMode:    false, // Default to false
	}
}

func (t *Tracer) Start(startFile string) {
	color.Cyan("[*] Sending Initialize (Source-Only Mode)...")
	rootUri := lsp.ToUri(t.ProjectRoot)

	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		if out, err := os.ReadFile("/usr/libexec/java_home"); err == nil {
			javaHome = strings.TrimSpace(string(out))
		}
	}
	if javaHome == "" {
		javaHome = "."
	}

	javaSettings := map[string]interface{}{
		"home": javaHome,
		"errors": map[string]interface{}{
			"incompleteClasspath": map[string]interface{}{"severity": "ignore"},
		},
		"configuration": map[string]interface{}{
			"runtimes": []map[string]interface{}{
				{"name": "JavaSE-1.8", "path": javaHome, "default": true},
				{"name": "JavaSE-11", "path": javaHome, "default": true},
				{"name": "JavaSE-17", "path": javaHome, "default": true},
			},
		},
		"import": map[string]interface{}{
			"gradle":     map[string]interface{}{"enabled": false},
			"maven":      map[string]interface{}{"enabled": false},
			"exclusions": []string{"**/pom.xml", "**/build.gradle"},
		},
	}

	caps := map[string]interface{}{
		"workspace": map[string]interface{}{
			"applyEdit":              true,
			"workspaceFolders":       true,
			"configuration":          true,
			"didChangeConfiguration": map[string]interface{}{"dynamicRegistration": true},
		},
		"textDocument": map[string]interface{}{
			"synchronization": map[string]interface{}{"didOpen": true, "didSave": true},
			"documentSymbol":  map[string]interface{}{"hierarchicalDocumentSymbolSupport": true},
			"references":      map[string]interface{}{"dynamicRegistration": true},
		},
	}

	initOpts := map[string]interface{}{
		"bundles":                    []string{},
		"extendedClientCapabilities": map[string]interface{}{"progressReportProvider": true},
		"settings":                   map[string]interface{}{"java": javaSettings},
	}

	t.Client.SendRequest("initialize", lsp.InitializeParams{
		RootUri:               rootUri,
		Capabilities:          caps,
		InitializationOptions: initOpts,
		WorkspaceFolders:      []lsp.WorkspaceFolder{{Uri: rootUri, Name: "Target"}},
	})

	t.Client.SendRequest("initialized", struct{}{})
	t.Client.SendNotification("workspace/didChangeConfiguration", map[string]interface{}{
		"settings": map[string]interface{}{"java": javaSettings},
	})
	t.sendDidOpen(startFile)

	color.Cyan("[*] Waiting for JDT.LS to be fully ready...")
	t.Client.WaitForServiceReady(15 * time.Second)
	color.Green("[+] Index Ready!")
}

func (t *Tracer) sendDidOpen(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	t.Client.SendRequest("textDocument/didOpen", map[string]interface{}{
		"textDocument": map[string]interface{}{
			"uri":        lsp.ToUri(path),
			"languageId": "java",
			"version":    1,
			"text":       string(content),
		},
	})
}

func (t *Tracer) WaitForReady(uri string) {
	t.Client.SendRequest("textDocument/documentSymbol", map[string]interface{}{
		"textDocument": map[string]string{"uri": uri},
	})
}

func (t *Tracer) GetEnclosingFunction(uri string, line int) (string, int, int, int) {
	var symbols []lsp.DocumentSymbol
	normPath := lsp.NormalizePath(lsp.FromUri(uri))

	if cached, ok := t.SymbolCache[normPath]; ok {
		symbols = cached
	} else {
		id := t.Client.SendRequest("textDocument/documentSymbol", map[string]interface{}{
			"textDocument": map[string]string{"uri": uri},
		})
		raw, err := t.Client.WaitForResult(id, 3*time.Second)
		if err != nil {
			return "", 0, 0, 0
		}
		json.Unmarshal(raw, &symbols)
		t.SymbolCache[normPath] = symbols
	}

	var foundName string
	var foundLine int
	var foundEndLine int
	var foundCol int

	var walk func([]lsp.DocumentSymbol)
	walk = func(nodes []lsp.DocumentSymbol) {
		for _, node := range nodes {
			if node.Range.Start.Line <= line && node.Range.End.Line >= line {
				if node.Kind == 6 || node.Kind == 12 {
					foundName = node.Name
					foundLine = node.SelectionRange.Start.Line
					foundEndLine = node.Range.End.Line
					foundCol = node.SelectionRange.Start.Character
				}
				if len(node.Children) > 0 {
					walk(node.Children)
				}
			}
		}
	}
	walk(symbols)
	return foundName, foundLine, foundEndLine, foundCol
}

func (t *Tracer) isFrameworkEntry(file string, line int) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	// Scan from the beginning of the file to catch Class-level annotations (e.g. @Controller)
	// and Method definitions that might be far above the sink.
	startScanLine := 0

	scanner := bufio.NewScanner(f)
	currLine := 0

	entryAnnotations := []string{
		// 1. Web MVC / REST (Spring Boot)
		"@RequestMapping", "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping", "@PatchMapping",
		"@Controller", "@RestController",

		// 2. Standard Java EE / Jakarta EE Web
		"@WebFilter", "@WebServlet",
		"implements Filter", "extends HttpServlet", "extends GenericServlet",

		// 3. Messaging (External Inputs)
		"@RabbitListener", "@KafkaListener", "@JmsListener",

		// REMOVED: @Component, @Service, @Repository (Too broad, internal structure)
		// REMOVED: @PostConstruct, @Scheduled (Internal lifecycle/timers, not external input)
	}

	for scanner.Scan() {
		if currLine >= startScanLine && currLine <= line {
			text := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(text, "//") || strings.HasPrefix(text, "*") {
				currLine++
				continue
			}
			for _, ann := range entryAnnotations {
				if strings.Contains(text, ann) {
					return true
				}
			}
		}
		if currLine > line {
			break
		}
		currLine++
	}
	return false
}

func (t *Tracer) TraceChain(file string, line int, col int, stack []model.ChainStep) {
	if t.isFrameworkEntry(file, line) {
		t.RecordResult(stack)
		return
	}

	uri := lsp.ToUri(file)
	maxRetries := 3

	var validRefs []lsp.Location

	for attempt := 1; attempt <= maxRetries; attempt++ {
		id := t.Client.SendRequest("textDocument/references", map[string]interface{}{
			"textDocument": map[string]string{"uri": uri},
			"position":     lsp.Position{Line: line, Character: col},
			"context":      map[string]bool{"includeDeclaration": true},
		})

		raw, _ := t.Client.WaitForResult(id, 2*time.Second)
		var refs []lsp.Location
		json.Unmarshal(raw, &refs)

		validRefs = []lsp.Location{}
		for _, ref := range refs {
			path := lsp.FromUri(ref.Uri)
			refLine := ref.Range.Start.Line
			if lsp.NormalizePath(path) == lsp.NormalizePath(file) && abs(refLine-line) <= 1 {
				continue
			}
			if filepath.Ext(path) == ".java" {
				validRefs = append(validRefs, ref)
			}
		}

		if len(validRefs) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(validRefs) == 0 {
		t.RecordResult(stack)
		return
	}

	for _, ref := range validRefs {
		callerPath := lsp.FromUri(ref.Uri)
		callerLine := ref.Range.Start.Line

		key := fmt.Sprintf("%s:%d", callerPath, callerLine)
		if t.Visited[key] {
			continue
		}
		t.Visited[key] = true

		// 1. 获取包围函数 (Enclosing Function) - 必须先获取，用于参数分析
		funcName, funcLine, _, funcCol := t.GetEnclosingFunction(ref.Uri, callerLine)
		if funcName == "" {
			funcName = "Global/Anonymous"
		}

		// 2. 分析调用点 (传入 funcName 以识别方法参数)
		analysisData := AnalyzeCallSite(callerPath, callerLine, funcName)

		fmt.Printf("    [↑] Found caller: %s (in %s:%d)\n", funcName, filepath.Base(callerPath), callerLine+1)

		newStep := model.ChainStep{
			File:     callerPath,
			Line:     callerLine,
			Func:     funcName,
			Code:     analysisData.Code,
			Analysis: analysisData.DataFlow,
		}

		if funcLine > 0 {
			t.TraceChain(callerPath, funcLine, funcCol, append(stack, newStep))
		} else {
			t.RecordResult(append(stack, newStep))
		}
	}
}

func (t *Tracer) RecordResult(stack []model.ChainStep) {
	// Strict Mode Check
	if t.StrictMode && len(stack) > 0 {
		sourceStep := stack[len(stack)-1]

		// Create a synthetic "Source" check: must be a framework entry point
		if !t.isFrameworkEntry(sourceStep.File, sourceStep.Line) {
			// Skip logging to avoid noise, or log debug
			// fmt.Printf("\r    [Strict] Skipped chain ending at %s (Not an Entry Point)\n", sourceStep.Func)
			return
		}

		// ✨ Check for Implicit Inputs (aka 0-arg method check) ✨
		funcName, startLine, endLine, _ := t.GetEnclosingFunction(lsp.ToUri(sourceStep.File), sourceStep.Line)
		if funcName != "" {
			if !t.checkSourceValidity(sourceStep.File, startLine, endLine) {
				return
			}
		}
	}

	// 1. Valid Chain found. Store a COPY of the stack to prevent aliasing issues
	// because the underlying array might be modified by the caller's loop.
	finalStack := make([]model.ChainStep, len(stack))
	copy(finalStack, stack)
	t.Results = append(t.Results, finalStack)

	// 2. 准备颜色工具
	boldRed := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()
	faint := color.New(color.Faint).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	// 3. 打印 ASCII 报告头
	fmt.Println()
	fmt.Println(strings.Repeat(faint("-"), 60))
	fmt.Printf("%s Found Vulnerability Chain (%d steps)\n", boldRed("🔥 [TRACE]"), len(stack))
	fmt.Println(strings.Repeat(faint("-"), 60))

	// 4. 逆序打印 (从 Source -> Sink)
	for i := len(stack) - 1; i >= 0; i-- {
		step := stack[i]

		var tag string
		if i == len(stack)-1 {
			tag = boldRed("🟥 SOURCE")
		} else if i == 0 {
			tag = boldRed("💀 SINK  ")
		} else {
			tag = yellow("🔸 STEP  ")
		}

		fmt.Printf(" %s: %s\n", tag, white(step.Func))

		// ✨✨✨ 这里仅为了显示美观，计算一次相对路径 ✨✨✨
		displayPath := step.File
		if rel, err := filepath.Rel(t.ProjectRoot, step.File); err == nil {
			displayPath = rel
		}

		fileInfo := fmt.Sprintf("%s:%d", displayPath, step.Line+1)
		fmt.Printf("     %s: %s\n", faint("File"), cyan(fileInfo))

		if step.Code != "" {
			cleanCode := strings.TrimSpace(step.Code)
			if len(cleanCode) > 100 {
				cleanCode = cleanCode[:100] + "..."
			}
			fmt.Printf("     %s: `%s`\n", faint("Code"), white(cleanCode))
		}

		for _, info := range step.Analysis {
			var coloredInfo string
			if strings.Contains(info, "🟢") {
				coloredInfo = green(info)
			} else if strings.Contains(info, "🚨") {
				coloredInfo = boldRed(info)
			} else {
				coloredInfo = yellow(info)
			}
			fmt.Printf("     %s\n", coloredInfo)
		}

		if i > 0 {
			fmt.Printf("        %s\n", faint("↓"))
		}
	}
	fmt.Println(strings.Repeat(faint("-"), 60))
	fmt.Println()
}

func (t *Tracer) checkSourceValidity(file string, startLine, endLine int) bool {
	f, err := os.Open(file)
	if err != nil {
		return true // Fail open
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	curr := 0
	for scanner.Scan() {
		if curr >= startLine && curr <= endLine {
			lines = append(lines, scanner.Text())
		}
		curr++
	}

	// 1. Check Parameters (Heuristic: signature has non-whitespace args)
	signature := ""
	bodyStartIndex := 0
	for i, line := range lines {
		signature += line + " "
		if strings.Contains(line, "{") {
			bodyStartIndex = i
			break
		}
	}

	argStart := strings.Index(signature, "(")
	argEnd := strings.LastIndex(signature, ")")

	hasParams := false
	if argStart != -1 && argEnd > argStart {
		args := strings.TrimSpace(signature[argStart+1 : argEnd])
		if len(args) > 0 {
			hasParams = true
		}
	}

	if hasParams {
		return true
	}

	// 2. Check Implicit Inputs in Body
	implicitKeywords := []string{
		"RequestContextHolder",
		"ServletRequestAttributes",
		"HttpServletRequest",
		"SecurityContextHolder",
		"request.getParameter",
		"request.getHeader",
		"request.getCookie",
		"MultipartHttpServletRequest",
	}

	fullBody := strings.Join(lines[bodyStartIndex:], "\n")
	for _, kw := range implicitKeywords {
		if strings.Contains(fullBody, kw) {
			return true
		}
	}

	return false
}
