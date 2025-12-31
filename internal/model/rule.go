package model

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SinkRule 定义一个漏洞规则
type SinkRule struct {
	Name       string         `yaml:"name"`        // 漏洞名称
	VulnType   string         `yaml:"vuln_type"`   // 漏洞类型
	Desc       string         `yaml:"desc"`        // 漏洞描述
	Severity   string         `yaml:"severity"`    // 严重等级
	ClassName  string         `yaml:"class_name"`  // 目标类全限定名
	MethodName string         `yaml:"method_name"` // 目标方法名
	Pattern    *regexp.Regexp `yaml:"-"`           // 正则匹配模式 (运行时生成)
	SkipSafe   bool           `yaml:"skip_safe"`   // 是否跳过常量参数
	IsStatic   bool           `yaml:"is_static"`   // 是否为静态方法
}

// LoadRulesFromFile 从 YAML 文件加载规则
func LoadRulesFromFile(path string) ([]SinkRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rules []SinkRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	// Post-process: Compile regex patterns
	for i := range rules {
		rules[i].Compile()
	}

	return rules, nil
}

// Compile 预编译规则的正则
func (r *SinkRule) Compile() {
	shortClass := r.ClassName
	if idx := strings.LastIndex(r.ClassName, "."); idx != -1 {
		shortClass = r.ClassName[idx+1:]
	}

	if r.Name == "" {
		r.Name = fmt.Sprintf("%s (%s.%s)", r.VulnType, shortClass, r.MethodName)
	}

	if r.MethodName == "<init>" {
		r.Pattern = regexp.MustCompile(`new\s+` + regexp.QuoteMeta(shortClass) + `\s*\(`)
	} else {
		r.Pattern = regexp.MustCompile(`\.` + regexp.QuoteMeta(r.MethodName) + `\s*\(`)
	}
}

// GetBuiltinRules 返回内置的“高置信度”规则库
func GetBuiltinRules() []SinkRule {
	rules := []SinkRule{}

	add := func(vulnType, desc, severity, className, methodName string, skipSafe bool, isStatic bool) {
		shortClass := className
		if idx := strings.LastIndex(className, "."); idx != -1 {
			shortClass = className[idx+1:]
		}

		name := fmt.Sprintf("%s (%s.%s)", vulnType, shortClass, methodName)

		var pat *regexp.Regexp
		if methodName == "<init>" {
			pat = regexp.MustCompile(`new\s+` + regexp.QuoteMeta(shortClass) + `\s*\(`)
		} else {
			pat = regexp.MustCompile(`\.` + regexp.QuoteMeta(methodName) + `\s*\(`)
		}

		rules = append(rules, SinkRule{
			Name:       name,
			VulnType:   vulnType,
			Desc:       desc,
			Severity:   severity,
			ClassName:  className,
			MethodName: methodName,
			Pattern:    pat,
			SkipSafe:   skipSafe,
			IsStatic:   isStatic,
		})
	}

	// ================= RCE (任意代码执行) =================
	// 只监控真正的执行方法
	add("RCE", "任意代码执行漏洞", "High", "java.lang.Runtime", "exec", true, false)
	// getRuntime() 只是获取单例，不是 sink
	add("RCE", "任意代码执行漏洞", "High", "java.lang.ProcessBuilder", "start", false, false)
	// new ProcessBuilder("cmd") 是危险的，因为后续通常紧跟 start()
	add("RCE", "任意代码执行漏洞", "High", "java.lang.ProcessBuilder", "<init>", true, false)
	add("RCE", "任意代码执行漏洞", "High", "javax.script.ScriptEngine", "eval", true, false)
	add("RCE", "任意代码执行漏洞", "High", "groovy.lang.GroovyShell", "evaluate", true, false)
	add("RCE", "任意代码执行漏洞", "High", "org.codehaus.groovy.runtime.InvokerHelper", "runScript", true, true) // Static

	// ================= UNSERIALIZE (反序列化) =================
	// 这些通常是高危的，误报较少
	add("UNSERIALIZE", "反序列化漏洞", "High", "java.io.ObjectInputStream", "readObject", false, false)
	add("UNSERIALIZE", "反序列化漏洞", "High", "org.yaml.snakeyaml.Yaml", "load", false, false)
	add("UNSERIALIZE", "反序列化漏洞", "High", "com.thoughtworks.xstream.XStream", "fromXML", false, false)
	// FastJSON/Gson 太多用于正常业务数据传输，建议视情况开启，或者只监控 parseObject
	add("UNSERIALIZE", "反序列化漏洞", "High", "com.alibaba.fastjson.JSON", "parseObject", false, true) // Static

	// ================= SSRF (服务端请求伪造) =================
	// ❌ 移除了 new URL(...)，因为它太常见且不一定会发起请求
	// 只监控发起连接的操作
	add("SSRF", "服务端请求伪造漏洞", "Medium", "java.net.URL", "openConnection", false, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "java.net.URL", "openStream", false, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "org.apache.http.client.HttpClient", "execute", true, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "org.apache.http.impl.client.CloseableHttpClient", "execute", true, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "okhttp3.OkHttpClient", "newCall", true, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "org.springframework.web.client.RestTemplate", "exchange", true, false)
	add("SSRF", "服务端请求伪造漏洞", "Medium", "org.springframework.web.client.RestTemplate", "getForObject", true, false)

	// ================= SQLI (SQL注入) =================
	// ❌ 移除了纯粹的 Connection 获取，聚焦在执行和预编译
	add("SQLI", "SQL注入漏洞", "High", "java.sql.Statement", "execute", true, false)
	add("SQLI", "SQL注入漏洞", "High", "java.sql.Statement", "executeQuery", true, false)
	add("SQLI", "SQL注入漏洞", "High", "java.sql.Statement", "executeUpdate", true, false)
	// prepareStatement 是 SQL 注入发生的时刻 (预编译字符串拼接)
	add("SQLI", "SQL注入漏洞", "High", "java.sql.Connection", "prepareStatement", true, false)
	add("SQLI", "SQL注入漏洞", "High", "org.mybatis.spring.SqlSessionTemplate", "selectOne", true, false)
	add("SQLI", "SQL注入漏洞", "High", "org.mybatis.spring.SqlSessionTemplate", "selectList", true, false)
	add("SQLI", "SQL注入漏洞", "High", "javax.persistence.EntityManager", "createNativeQuery", true, false)
	add("SQLI", "SQL注入漏洞", "High", "com.jfinal.plugin.activerecord.Db", "find", true, true) // Static

	// ================= XSS (跨站脚本) =================
	// ❌ 移除了 getWriter, getOutputStream, getResponse 等“获取流”的操作
	// 只监控“写入”操作
	add("XSS", "跨站脚本漏洞", "Medium", "java.io.PrintWriter", "write", true, false)
	add("XSS", "跨站脚本漏洞", "Medium", "java.io.PrintWriter", "print", true, false)
	// JSP/Servlet 输出
	add("XSS", "跨站脚本漏洞", "Medium", "javax.servlet.jsp.JspWriter", "print", true, false)
	add("XSS", "跨站脚本漏洞", "Medium", "javax.servlet.jsp.JspWriter", "write", true, false)
	// 模板引擎渲染上下文 (比较容易误报，视情况保留)
	add("XSS", "跨站脚本漏洞", "Medium", "org.springframework.web.servlet.ModelAndView", "addObject", true, false)
	add("XSS", "跨站脚本漏洞", "Medium", "org.springframework.web.servlet.ModelMap", "addAttribute", true, false)

	// ================= PATH_TRAVERSAL (路径遍历) =================
	// ❌ 移除了 new File(...)，这是误报之王。
	// 改为监控具体的 IO 操作工具类，它们通常直接操作流
	add("PATH_TRAVERSAL", "路径遍历漏洞", "Medium", "java.nio.file.Files", "newInputStream", true, true)              // Static
	add("PATH_TRAVERSAL", "路径遍历漏洞", "Medium", "java.nio.file.Files", "write", true, true)                       // Static
	add("PATH_TRAVERSAL", "路径遍历漏洞", "Medium", "org.apache.commons.io.FileUtils", "openInputStream", true, true) // Static
	add("PATH_TRAVERSAL", "路径遍历漏洞", "Medium", "org.springframework.util.FileCopyUtils", "copy", true, true)     // Static
	// FileInputStream 也是个很好的 Sink，但 new FileInputStream(file) 很难正则匹配，因为 file 可能是对象
	// 如果参数是 String，可以监控
	add("PATH_TRAVERSAL", "路径遍历漏洞", "Medium", "java.io.FileInputStream", "<init>", true, false)

	// ================= XXE (XML外部实体注入) =================
	add("XXE", "XML外部实体注入", "High", "javax.xml.parsers.DocumentBuilder", "parse", true, false)
	add("XXE", "XML外部实体注入", "High", "javax.xml.parsers.SAXParser", "parse", true, false)
	add("XXE", "XML外部实体注入", "High", "org.dom4j.io.SAXReader", "read", true, false)

	// ================= REDIRECT (URL重定向) =================
	add("REDIRECT", "URL重定向", "Medium", "javax.servlet.http.HttpServletResponse", "sendRedirect", true, false)
	add("REDIRECT", "URL重定向", "Medium", "org.springframework.web.servlet.view.RedirectView", "<init>", true, false)

	return rules
}
