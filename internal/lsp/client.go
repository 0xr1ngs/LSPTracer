package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)


type Client struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	msgId     int
	mu        sync.Mutex
	isRunning bool
}

func NewClient(cmd *exec.Cmd) (*Client, error) {
	// 1. 获取 Stdin Pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	// 2. 获取 Stdout Pipe
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// 3. 获取 Stderr Pipe
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	
	// 4. 启动进程 (cmd 已经在外部被配置好了 Args 和 Env)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// 5. 启动 goroutine 处理 stderr
	// 直接把 JDTLS 的错误日志导向 os.Stderr，方便调试
	go io.Copy(os.Stderr, stderrPipe)

	return &Client{
		cmd:       cmd,
		stdin:     stdin,
		stdout:    bufio.NewReader(stdoutPipe),
		isRunning: true,
	}, nil
}

func (c *Client) Close() {
	if c.isRunning && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		c.isRunning = false
	}
}

// 发送请求
func (c *Client) SendRequest(method string, params interface{}) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgId++

	req := JsonRpcMessage{
		JsonRpc: "2.0",
		Id:      c.msgId,
		Method:  method,
		Params:  params,
	}
	
	c.write(req)
	return c.msgId
}

// 发送通知
func (c *Client) SendNotification(method string, params interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := JsonRpcMessage{
		JsonRpc: "2.0",
		Method:  method,
		Params:  params,
	}
	
	c.write(req)
}

// 写入数据到底层 Pipe
func (c *Client) write(msg interface{}) {
	body, _ := json.Marshal(msg)
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	c.stdin.Write([]byte(header))
	c.stdin.Write(body)
}

// 等待特定的响应结果
func (c *Client) WaitForResult(targetId int, timeout time.Duration) (json.RawMessage, error) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		line, err := c.stdout.ReadString('\n')
		if err != nil { return nil, err }
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "Content-Length:") {
			lengthStr := strings.TrimPrefix(line, "Content-Length:")
			length, _ := strconv.Atoi(strings.TrimSpace(lengthStr))
			c.stdout.ReadString('\n') // 读掉空行
			
			bodyBuf := make([]byte, length)
			_, err := io.ReadFull(c.stdout, bodyBuf)
			if err != nil { return nil, err }

			var msg JsonRpcMessage
			if err := json.Unmarshal(bodyBuf, &msg); err != nil { continue }

			// [DEBUG] 可以在这里过滤 Diagnostics，目前静音
			// if msg.Method == "textDocument/publishDiagnostics" { ... }

			// 检查是否是我们等待的 ID
			// 注意：msg.Id 解析出来可能是 float64，需要转一下
			if msg.Id != nil {
				var currentId int
				switch v := msg.Id.(type) {
				case float64:
					currentId = int(v)
				case int:
					currentId = v
				}

				if currentId == targetId {
					if msg.Error != nil {
						// 如果 Server 返回 Error，也应该处理，但在简化版里我们先忽略或打印
						// fmt.Printf("LSP Error: %v\n", msg.Error)
						return nil, fmt.Errorf("server returned error")
					}
					return msg.Result, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("timeout")
}

// 等待 JDT.LS 就绪，同时打印进度日志
func (c *Client) WaitForServiceReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	fmt.Printf("    -> Waiting for JDT.LS 'ServiceReady' signal...\n")

	for time.Now().Before(deadline) {
		// 1. 读取头部
		line, err := c.stdout.ReadString('\n')
		if err != nil { return err } // 进程如果崩了，这里会报错
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "Content-Length:") {
			// 2. 解析长度
			lengthStr := strings.TrimPrefix(line, "Content-Length:")
			length, _ := strconv.Atoi(strings.TrimSpace(lengthStr))
			c.stdout.ReadString('\n') // 读掉空行
			
			// 3. 读取 Body
			bodyBuf := make([]byte, length)
			_, err := io.ReadFull(c.stdout, bodyBuf)
			if err != nil { return err }

			// 4. 解析消息
			var msg JsonRpcMessage
			if err := json.Unmarshal(bodyBuf, &msg); err != nil { continue }

			// ✨✨✨ 新增：打印日志消息 (让等待不再枯燥) ✨✨✨
			if msg.Method == "window/logMessage" {
				paramsMap, ok := msg.Params.(map[string]interface{})
				if ok {
					// type: 1=Error, 2=Warning, 3=Info, 4=Log
					// msgType, _ := paramsMap["type"].(float64) 
					message, _ := paramsMap["message"].(string)
					
					// 过滤掉太长的垃圾日志，只显示关键进度
					if len(message) < 200 {
						// 覆盖打印，制造动画效果
						// \r 回到行首，\033[K 清除当前行
						fmt.Printf("\r\033[K    -> [JDT.LS] %s", message)
					}
				}
			}

			// 5. 判断是否是 language/status (核心信号)
			if msg.Method == "language/status" {
				paramsMap, ok := msg.Params.(map[string]interface{})
				if ok {
					msgType, _ := paramsMap["type"].(string)
					msgText, _ := paramsMap["message"].(string)

					// 打印状态
					fmt.Printf("\r\033[K    -> Server Status: %s - %s", msgType, msgText)

					// ✨ 核心：如果是 ServiceReady，说明 Maven 构建彻底完了！
					if msgType == "ServiceReady" {
						fmt.Println() // 换行，结束等待
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("timeout waiting for ServiceReady")
}