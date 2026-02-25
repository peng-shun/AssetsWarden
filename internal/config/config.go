package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 是 AssetsWarden 的配置结构体
type Config struct {
	ProtectedPaths []string `yaml:"protected_paths"`
	MonitoredUsers []string `yaml:"monitored_users"`
	LogLevel       string   `yaml:"log_level"`
	LLM            LLMConfig `yaml:"llm"`
	MCP            MCPConfig `yaml:"mcp"`
}

// LLMConfig 是 LLM 分析器的配置
type LLMConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Endpoint   string `yaml:"endpoint"`
	APIKeyEnv  string `yaml:"api_key_env"`
	Model      string `yaml:"model"`
}

// MCPConfig 是 MCP 服务端的配置
type MCPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Transport string `yaml:"transport"` // "stdio" | "sse"
}

// APIKey 返回从环境变量读取的 API key
func (l *LLMConfig) APIKey() string {
	if l.APIKeyEnv == "" {
		return ""
	}
	return os.Getenv(l.APIKeyEnv)
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		LogLevel: "info",
		LLM: LLMConfig{
			Enabled:   false,
			Endpoint:  "https://api.example.com/v1/chat/completions",
			APIKeyEnv: "ASSETWARDEN_LLM_API_KEY",
			Model:     "claude-sonnet-4-20250514",
		},
		MCP: MCPConfig{
			Enabled:   true,
			Transport: "stdio",
		},
	}
}

// LoadConfig 从 YAML 文件加载配置，并和默认配置合并
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config file: %w", err)
	}

	// 验证保护路径存在
	for _, p := range cfg.ProtectedPaths {
		if _, err := os.Stat(p); err != nil {
			return cfg, fmt.Errorf("protected path %q: %w", p, err)
		}
	}

	return cfg, nil
}

// String 用于调试输出（脱敏）
func (c Config) String() string {
	return fmt.Sprintf(
		"Config{ProtectedPaths: [%s], MonitoredUsers: [%s], LLM.Enabled: %v, MCP.Transport: %s}",
		strings.Join(c.ProtectedPaths, ", "),
		strings.Join(c.MonitoredUsers, ", "),
		c.LLM.Enabled,
		c.MCP.Transport,
	)
}
