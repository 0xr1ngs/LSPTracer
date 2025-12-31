package lsp

import "encoding/json"

// 通用 JSON-RPC 消息
type JsonRpcMessage struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      interface{}     `json:"id,omitempty"` // ID 可以是 int, string 或 nil
	Method  string          `json:"method,omitempty"`
	Params  interface{}     `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
}


// 初始化参数
type InitializeParams struct {
	RootUri               string                 `json:"rootUri"`
	WorkspaceFolders      []WorkspaceFolder      `json:"workspaceFolders"`
	Capabilities          map[string]interface{} `json:"capabilities"`
	InitializationOptions interface{}            `json:"initializationOptions,omitempty"`
}

type WorkspaceFolder struct {
	Uri  string `json:"uri"`
	Name string `json:"name"`
}

type Location struct {
	Uri   string `json:"uri"`
	Range Range  `json:"range"`
}

type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type DocumentSymbol struct {
	Name           string           `json:"name"`
	Kind           int              `json:"kind"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}