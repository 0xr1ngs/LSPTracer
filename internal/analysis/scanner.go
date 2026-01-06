package analysis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LSPTracer/internal/lsp"
	"LSPTracer/internal/model"

	"github.com/fatih/color"
)

// 候选点结构
type candidate struct {
	File string
	Line int
	Col  int
	Code string
	Rule model.SinkRule
}

func (t *Tracer) ScanAndTrace(rules []model.SinkRule) {
	color.Cyan("\n[*] Starting Smart Vulnerability Scan...")

	// 1. 文本初筛 + 常量过滤
	candidates := t.findCandidates(rules)
	color.Blue("[*] Found %d potential risky sinks (Text Match).", len(candidates))
	color.Blue("[*] Verifying candidates with LSP (Loose Mode)...")

	processedSinks := make(map[string]bool)
	realSinks := 0

	for i, cand := range candidates {
		// 打印进度
		fmt.Printf("\r    [%d/%d] Checking: %s", i+1, len(candidates), truncateString(cand.Code, 40))

		sinkKey := fmt.Sprintf("%s:%d", cand.File, cand.Line)
		if processedSinks[sinkKey] {
			continue
		}

		// 2. LSP 验身 (或 heuristic 兜底)
		if t.verifySink(cand) {

			// 3. 启发式二次检查 (Heuristic Filter)

			realSinks++
			processedSinks[sinkKey] = true

			fmt.Print("\r                                                                 \r")
			color.Red("[+] Confirmed Sink: %s", strings.TrimSpace(cand.Code))
			fmt.Printf("    File: %s:%d\n", filepath.Base(cand.File), cand.Line+1)

			t.ReportedEntry = make(map[string]bool)

			firstStep := model.ChainStep{
				File:     cand.File,
				Line:     cand.Line,
				Func:     "Sink Detection",
				Code:     cand.Code,
				Analysis: []string{fmt.Sprintf("🚨 Matched Rule: %s", cand.Rule.Name)},
			}

			// Get Enclosing Function Name FIRST
			funcName, fLine, _, fCol := t.GetEnclosingFunction(lsp.ToUri(cand.File), cand.Line)

			// Analyze Variable Definition using Enclosing Function Name
			analysisRes := AnalyzeCallSite(cand.File, cand.Line, funcName)
			firstStep.Analysis = append(firstStep.Analysis, analysisRes.DataFlow...)

			if funcName != "" {
				firstStep.Func = funcName

				// Acquire semaphore slot
				t.Sem <- struct{}{}
				t.Wg.Add(1)

				go func(file string, line, col int, stack []model.ChainStep) {
					defer func() {
						<-t.Sem
						t.Wg.Done()
					}()
					// Initialize per-chain visited map
					initialVisited := make(map[string]bool)
					t.TraceChain(file, line, col, stack, initialVisited)
				}(cand.File, fLine, fCol, []model.ChainStep{firstStep})

			} else {
				// FIX: Route through RecordResult to enforce Strict Mode check
				// (Previously: t.Results = append(t.Results, []model.ChainStep{firstStep}))
				// Even for orphan sinks, we must pass them through RecordResult validation.
				t.RecordResult([]model.ChainStep{firstStep})
			}
		}
	}

	// Wait for all trace chains to complete
	color.Cyan("[*] Waiting for all trace chains to complete...")
	t.Wg.Wait()
	fmt.Println()

	if realSinks == 0 {
		color.Yellow("\n[-] No confirmed vulnerabilities found.")
	} else {
		color.Green("\n[+] Scan finished. Found %d confirmed vulnerability chains.", len(t.Results))
	}
}

func (t *Tracer) findCandidates(rules []model.SinkRule) []candidate {
	var results []candidate

	filepath.Walk(t.ProjectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".java") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0

		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())

			if strings.HasPrefix(text, "//") || strings.HasPrefix(text, "*") || strings.HasPrefix(text, "/*") {
				lineNum++
				continue
			}

			for _, rule := range rules {
				var idx int
				if rule.Pattern != nil {
					loc := rule.Pattern.FindStringIndex(text)
					if loc != nil {
						idx = loc[0]
					} else {
						idx = -1
					}
				} else {
					idx = strings.Index(text, rule.MethodName+"(")
				}

				if idx != -1 {
					// ✨✨✨ 这里直接调用 utils.go 里的 isStrictConstant ✨✨✨
					if rule.SkipSafe && isStrictConstant(extractArgs(text)) {
						continue
					}
					results = append(results, candidate{
						File: path,
						Line: lineNum,
						Col:  idx,
						Code: text,
						Rule: rule,
					})
				}
			}
			lineNum++
		}
		return nil
	})
	return results
}

func (t *Tracer) verifySink(cand candidate) bool {
	uri := lsp.ToUri(cand.File)
	id := t.Client.SendRequest("textDocument/definition", map[string]interface{}{
		"textDocument": map[string]string{"uri": uri},
		"position":     lsp.Position{Line: cand.Line, Character: cand.Col + 1},
	})

	// 增加超时时间到 3秒，减少因索引未完成导致的 False Negative
	res, err := t.Client.WaitForResult(id, 3*time.Second)

	// Revert Strict Mode: 如果 LSP 失败或超时，由于我们处于无依赖环境，
	// 默认认为可能是 Sink (Loose Mode) 以防漏报。
	// 但我们会随后用 heuristic check 来剔除明显的误报。
	if err != nil || res == nil || strings.TrimSpace(string(res)) == "[]" {
		return true
	}

	resStr := string(res)

	targetPath := strings.ReplaceAll(cand.Rule.ClassName, ".", "/")
	shortName := cand.Rule.ClassName
	if idx := strings.LastIndex(shortName, "."); idx != -1 {
		shortName = shortName[idx+1:]
	}

	if strings.Contains(resStr, targetPath) || strings.Contains(resStr, shortName) {
		return true
	}

	// 3. Fallback: Import Verification (Heuristic)
	// If LSP failed (e.g. source-only mode), we check if the file IMPORTS the target class.
	// Only if the class is imported do we consider it a potential match.
	if t.hasImport(cand.File, cand.Rule.ClassName) {
		return true
	}

	return false
}

// hasImport checks if a Java file imports a specific class
func (t *Tracer) hasImport(file string, className string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	pkgParts := strings.Split(className, ".")
	if len(pkgParts) < 2 {
		return false
	}
	// e.g., org.apache.http.client.HttpClient -> package: org.apache.http.client
	packageName := strings.Join(pkgParts[:len(pkgParts)-1], ".")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "import ") {
			// 1. Exact Import: import org.apache.http.client.HttpClient;
			if strings.Contains(line, className) {
				return true
			}
			// 2. Star Import: import org.apache.http.client.*;
			if strings.Contains(line, packageName+".*") {
				return true
			}
		}
		// Stop scanning at class definition (optimization)
		if strings.Contains(line, "class ") || strings.Contains(line, "interface ") {
			break
		}
	}
	return false
}
