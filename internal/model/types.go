package model

// ChainStep 定义了漏洞追踪链路中的一个节点
// 它是 analysis 和 report 共用的数据结构
type ChainStep struct {
	File     string
	Line     int
	Func     string
	Code     string
	Analysis []string
}