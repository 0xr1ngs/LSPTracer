package lang

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"LSPTracer/internal/env"
)

type JavaConfig struct {
	JdtlsHome  string
	JavaExec   string
	LombokPath string // ✨ 新增：明确指定 Lombok 路径
}

// BuildCmd 现在返回 *exec.Cmd，符合 LSP Client 的期望
func (c *JavaConfig) BuildCmd() (*exec.Cmd, error) {
	// 1. 寻找 launcher jar
	pluginsDir := filepath.Join(c.JdtlsHome, "plugins")
	launcherJar, err := findLauncherJar(pluginsDir)
	if err != nil { return nil, err }

	// 2. 确定 config 目录 (复用 env 包逻辑)
	configDir := env.GetJdtlsConfigDir(c.JdtlsHome)
	
	// 3. 准备数据目录
	dataDir, _ := filepath.Abs(".jdtls_data_cache")
	os.MkdirAll(dataDir, 0755)

	args := []string{
		"-Declipse.application=org.eclipse.jdt.ls.core.id1",
		"-Dosgi.bundles.defaultStartLevel=4",
		"-Declipse.product=org.eclipse.jdt.ls.core.product",
		"-Dlog.level=ALL",
		"-Xmx4G",
		"--add-modules=ALL-SYSTEM",
		"--add-opens", "java.base/java.util=ALL-UNNAMED",
		"--add-opens", "java.base/java.lang=ALL-UNNAMED",
		"--add-opens", "java.base/java.util.concurrent=ALL-UNNAMED",
		"--add-opens", "java.base/java.io=ALL-UNNAMED",
	}

	// ✨✨✨ 注入 Lombok Agent (如果有) ✨✨✨
	if c.LombokPath != "" {
		args = append(args, fmt.Sprintf("-javaagent:%s", c.LombokPath))
		// 某些高版本 JDK/Lombok 可能还需要 bootclasspath，加上更保险
		args = append(args, fmt.Sprintf("-Xbootclasspath/a:%s", c.LombokPath))
	}

	args = append(args,
		"-jar", launcherJar,
		"-configuration", configDir,
		"-data", dataDir,
	)

	return exec.Command(c.JavaExec, args...), nil
}

func findLauncherJar(dir string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(dir, "org.eclipse.equinox.launcher_*.jar"))
	if len(matches) == 0 {
		return "", fmt.Errorf("launcher jar not found in %s", dir)
	}
	return matches[0], nil
}