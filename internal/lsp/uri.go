package lsp

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
)

// ToUri 将文件路径转换为 LSP 协议的 URI
func ToUri(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	
	// Windows 补丁: C:\Users -> /C:/Users
	if runtime.GOOS == "windows" {
		abs = "/" + strings.ReplaceAll(abs, "\\", "/")
	}

	// 使用 url.PathEscape 处理空格等特殊字符
	u := url.URL{
		Scheme: "file",
		Path:   abs,
	}
	return u.String()
}

// FromUri 将 URI 转换为本地文件路径
func FromUri(uriStr string) string {
	u, err := url.Parse(uriStr)
	if err != nil {
		return uriStr // 解析失败原样返回
	}
	
	path := u.Path
	// Windows 补丁: /C:/Users -> C:\Users
	if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") {
		path = strings.TrimPrefix(path, "/")
	}
	return filepath.FromSlash(path)
}

// NormalizePath 用于比较路径时忽略大小写差异 (针对 Mac/Windows)
func NormalizePath(path string) string {
	abs, _ := filepath.Abs(path)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(abs)
	}
	return abs
}