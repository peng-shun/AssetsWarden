package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"assetwarden/internal/config"
	"assetwarden/internal/model"
)

// LLMAnalyzer 调用 LLM API 对拦截事件进行分析
type LLMAnalyzer struct {
	cfg    config.LLMConfig
	client *http.Client
}

// AnalysisResult 是 LLM 返回的分析结果
type AnalysisResult struct {
	RiskLevel   string `json:"risk_level"`   // "critical" / "warning" / "info"
	Explanation string `json:"explanation"`   // 人类可读的分析
	Suggestion  string `json:"suggestion"`    // 建议的响应动作
}

// NewLLMAnalyzer 创建 LLM 分析器
func NewLLMAnalyzer(cfg config.LLMConfig) *LLMAnalyzer {
	return &LLMAnalyzer{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Analyze 对拦截事件调用 LLM 进行分析
func (a *LLMAnalyzer) Analyze(ctx context.Context, event model.SyscallEvent) (*AnalysisResult, error) {
	if !a.cfg.Enabled {
		return nil, fmt.Errorf("LLM analyzer is disabled")
	}

	apiKey := a.cfg.APIKey()
	if apiKey == "" {
		return nil, fmt.Errorf("LLM API key not set (env: %s)", a.cfg.APIKeyEnv)
	}

	prompt := buildPrompt(event)

	// 构造 OpenAI compatible 请求体
	reqBody := map[string]any{
		"model": a.cfg.Model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": systemPrompt,
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM API call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("LLM API returned %d: %v", resp.StatusCode, errBody)
	}

	// 解析 OpenAI 响应格式
	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}
	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("empty choices in API response")
	}

	// 解析 LLM 输出的 JSON
	var result AnalysisResult
	if err := json.Unmarshal([]byte(apiResp.Choices[0].Message.Content), &result); err != nil {
		return nil, fmt.Errorf("parse LLM output: %w", err)
	}

	return &result, nil
}

const systemPrompt = `You are a security auditor for a Linux file system protection system called AssetsWarden.
You will receive information about an intercepted file system operation (delete or rename) that was blocked by an eBPF LSM hook.
Analyze the event and respond ONLY with a JSON object in this exact format:
{
  "risk_level": "critical|warning|info",
  "explanation": "A clear, concise explanation of what happened and why it might be concerning",
  "suggestion": "Recommended action for the security administrator"
}
Be concise but informative. Focus on the security implications.`

// buildPrompt 根据事件构造 LLM 的用户 prompt
func buildPrompt(event model.SyscallEvent) string {
	eventJSON, _ := json.MarshalIndent(map[string]any{
		"operation":  event.Operation.String(),
		"pid":        event.PID,
		"uid":        event.UID,
		"process":    event.Comm,
		"path":       event.Path,
		"dest_path":  event.DestPath,
		"timestamp":  time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339),
		"inode":      event.Ino,
		"dir_inode":  event.DirIno,
	}, "", "  ")

	return fmt.Sprintf("Blocked file system operation:\n```json\n%s\n```\n\nPlease analyze this security event.", string(eventJSON))
}
