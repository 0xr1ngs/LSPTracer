package env

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

const (
	// JDT.LS 官方 Latest Snapshot 地址
	JdtlsUrl = "https://download.eclipse.org/jdtls/snapshots/jdt-language-server-latest.tar.gz"
	// Lombok 官方下载地址
	LombokUrl = "https://projectlombok.org/downloads/lombok.jar"
	
	// 存放依赖的目录名
	DepsDirName = ".lsptracer_deps"
)

// EnsureEnv 检查并准备环境，返回 (jdtlsHome, lombokPath, error)
func EnsureEnv() (string, string, error) {
	// ✨✨✨ 修改：改为使用当前工作目录 (Project Root) ✨✨✨
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current working directory: %v", err)
	}
	
	// 依赖将下载到 ./ .lsptracer_deps
	depsRoot := filepath.Join(cwd, DepsDirName)
	
	jdtlsPath := filepath.Join(depsRoot, "jdtls")
	lombokPath := filepath.Join(depsRoot, "lombok.jar")

	// 创建目录
	if _, err := os.Stat(depsRoot); os.IsNotExist(err) {
		os.MkdirAll(depsRoot, 0755)
	}

	// 2. 检查并下载 JDT.LS
	if !exists(jdtlsPath) {
		color.Cyan("[*] Environment: JDT.LS not found.")
		if err := downloadAndExtractJdtls(JdtlsUrl, jdtlsPath); err != nil {
			return "", "", fmt.Errorf("failed to setup JDT.LS: %v", err)
		}
		color.Green("[+] Environment: JDT.LS installed to: %s", jdtlsPath)
	}

	// 3. 检查并下载 Lombok
	if !exists(lombokPath) {
		color.Cyan("[*] Environment: Lombok not found.")
		if err := downloadFile(LombokUrl, lombokPath, "Downloading Lombok"); err != nil {
			return "", "", fmt.Errorf("failed to download Lombok: %v", err)
		}
		color.Green("[+] Environment: Lombok installed to: %s", lombokPath)
	}

	return jdtlsPath, lombokPath, nil
}

// 辅助：文件/目录是否存在
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// 下载文件（带进度条）
func downloadFile(url string, dest string, description string) error {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("http status: %s", resp.Status)
	}

	out, err := os.Create(dest)
	if err != nil { return err }
	defer out.Close()

	// 初始化进度条
	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		description,
	)

	_, err = io.Copy(io.MultiWriter(out, bar), resp.Body)
	return err
}

// 下载并解压 JDT.LS (tar.gz)
func downloadAndExtractJdtls(url string, destDir string) error {
	// 1. 下载到临时文件
	tmpFile := filepath.Join(os.TempDir(), "jdtls_installer.tar.gz")
	
	if err := downloadFile(url, tmpFile, "Downloading JDT.LS"); err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	color.Cyan("    -> Extracting JDT.LS...")

	// 2. 解压
	if err := os.MkdirAll(destDir, 0755); err != nil { return err }
	
	f, err := os.Open(tmpFile)
	if err != nil { return err }
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil { return err }
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF { break }
		if err != nil { return err }

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil { return err }
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil { return err }
			
			outFile, err := os.Create(target)
			if err != nil { return err }
			
			mode := header.FileInfo().Mode()
			if strings.Contains(target, "/bin/") {
				mode = 0755
			}
			
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
			os.Chmod(target, mode)
		}
	}
	fmt.Println() 
	return nil
}

// 获取 JDTLS 的 config 目录名
func GetJdtlsConfigDir(home string) string {
	osName := runtime.GOOS
	switch osName {
	case "linux":
		return filepath.Join(home, "config_linux")
	case "darwin":
		return filepath.Join(home, "config_mac")
	case "windows":
		return filepath.Join(home, "config_win")
	default:
		return filepath.Join(home, "config_linux")
	}
}