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
	mu        sync.Mutex // Protects msgId and write
	isRunning bool

	// Async Response Handling
	pendingResponses map[int]chan json.RawMessage
	responseMu       sync.Mutex
	serviceReady     chan struct{}
	once             sync.Once
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
	go io.Copy(os.Stderr, stderrPipe)

	c := &Client{
		cmd:              cmd,
		stdin:            stdin,
		stdout:           bufio.NewReader(stdoutPipe),
		isRunning:        true,
		pendingResponses: make(map[int]chan json.RawMessage),
		serviceReady:     make(chan struct{}),
	}

	// 6. 启动专用读取协程
	go c.readLoop()

	return c, nil
}

func (c *Client) Close() {
	if c.isRunning && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		c.isRunning = false
	}
}

// readLoop 持续读取 stdout 并分发消息
func (c *Client) readLoop() {
	for {
		line, err := c.stdout.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Content-Length:") {
			lengthStr := strings.TrimPrefix(line, "Content-Length:")
			length, _ := strconv.Atoi(strings.TrimSpace(lengthStr))
			c.stdout.ReadString('\n') // 读掉空行

			bodyBuf := make([]byte, length)
			_, err := io.ReadFull(c.stdout, bodyBuf)
			if err != nil {
				return
			}

			var msg JsonRpcMessage
			if err := json.Unmarshal(bodyBuf, &msg); err != nil {
				continue
			}

			// 1. 处理日志/状态通知
			c.handleNotification(msg)

			// 2. 处理响应 (如果有 ID)
			if msg.Id != nil {
				var currentId int
				switch v := msg.Id.(type) {
				case float64:
					currentId = int(v)
				case int:
					currentId = v
				}

				c.responseMu.Lock()
				ch, ok := c.pendingResponses[currentId]
				c.responseMu.Unlock()

				if ok {
					// 非阻塞发送，防止 readLoop 卡死
					select {
					case ch <- msg.Result:
					default:
					}
				}
			}
		}
	}
}

func (c *Client) handleNotification(msg JsonRpcMessage) {
	if msg.Method == "window/logMessage" {
		paramsMap, ok := msg.Params.(map[string]interface{})
		if ok {
			message, _ := paramsMap["message"].(string)
			if len(message) < 200 {
				fmt.Printf("\r\033[K    -> [JDT.LS] %s", message)
			}
		}
	}

	if msg.Method == "language/status" {
		paramsMap, ok := msg.Params.(map[string]interface{})
		if ok {
			msgType, _ := paramsMap["type"].(string)
			msgText, _ := paramsMap["message"].(string)
			// 避免打印过长的状态信息，尤其是重复的 Refreshing
			if len(msgText) > 100 {
				msgText = msgText[:97] + "..."
			}
			fmt.Printf("\r\033[K    -> Server Status: %s - %s", msgType, msgText)

			if msgType == "ServiceReady" {
				c.once.Do(func() {
					close(c.serviceReady)
				})
				fmt.Println()
			}
		}
	}
}

// 发送请求
func (c *Client) SendRequest(method string, params interface{}) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgId++

	// 提前注册通道
	ch := make(chan json.RawMessage, 1)
	c.responseMu.Lock()
	c.pendingResponses[c.msgId] = ch
	c.responseMu.Unlock()

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
	c.responseMu.Lock()
	ch, ok := c.pendingResponses[targetId]
	c.responseMu.Unlock()

	if !ok {
		return nil, fmt.Errorf("request id %d not found or already processed", targetId)
	}

	defer func() {
		c.responseMu.Lock()
		delete(c.pendingResponses, targetId)
		c.responseMu.Unlock()
	}()

	select {
	case res := <-ch:
		return res, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout")
	}
}

// 等待 JDT.LS 就绪
func (c *Client) WaitForServiceReady(timeout time.Duration) error {
	fmt.Printf("    -> Waiting for JDT.LS 'ServiceReady' signal...\n")
	select {
	case <-c.serviceReady:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for ServiceReady")
	}
}
