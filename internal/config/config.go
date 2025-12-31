package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	JdtlsHome   string `yaml:"jdtls_home"`
	ProjectRoot string `yaml:"project_root"`
	Target      struct {
		File string `yaml:"file"`
		Line int    `yaml:"line"`
		Col  int    `yaml:"col"`
	} `yaml:"target"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}