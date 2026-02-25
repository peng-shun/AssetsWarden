package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"assetwarden/internal/analyzer"
	"assetwarden/internal/model"
	"assetwarden/internal/policy"
)

// Server 是 AssetsWarden 的 MCP 服务端
// 通过 stdio 或 SSE 暴露工具接口，供 AI agents 调用
type Server struct {
	mcpServer   *server.MCPServer
	pathPolicy  *policy.PathMatchPolicy
	uidPolicy   *policy.UIDFilterPolicy
	analyzer    *analyzer.LLMAnalyzer // 可为 nil（LLM 禁用时）
	events      []model.SyscallEvent  // 最近拦截事件
	mu          sync.RWMutex
	startTime   time.Time
}

// NewServer 创建 MCP 服务端
func NewServer(
	pathPolicy *policy.PathMatchPolicy,
	uidPolicy *policy.UIDFilterPolicy,
	llmAnalyzer *analyzer.LLMAnalyzer,
) *Server {
	s := &Server{
		pathPolicy: pathPolicy,
		uidPolicy:  uidPolicy,
		analyzer:   llmAnalyzer,
		startTime:  time.Now(),
	}

	srv := server.NewMCPServer(
		"AssetsWarden",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// 注册所有工具
	s.registerTools(srv)
	s.mcpServer = srv
	return s
}

// RecordEvent 记录拦截事件（由 daemon 调用）
func (s *Server) RecordEvent(evt model.SyscallEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
	// 只保留最近 1000 条
	if len(s.events) > 1000 {
		s.events = s.events[len(s.events)-1000:]
	}
}

// ServeStdio 在 stdio 上启动 MCP 服务
func (s *Server) ServeStdio(ctx context.Context) error {
	return server.ServeStdio(s.mcpServer)
}

// registerTools 注册所有 MCP 工具
func (s *Server) registerTools(srv *server.MCPServer) {
	// get_status
	srv.AddTool(mcp.NewTool("get_status",
		mcp.WithDescription("Get AssetsWarden daemon status"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		s.mu.RLock()
		eventCount := len(s.events)
		s.mu.RUnlock()
		data := map[string]any{
			"status":       "running",
			"uptime":       time.Since(s.startTime).String(),
			"event_count":  eventCount,
		}
		return jsonResult(data)
	})

	// list_protected_paths
	srv.AddTool(mcp.NewTool("list_protected_paths",
		mcp.WithDescription("List currently protected paths"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		paths := s.pathPolicy.Protected()
		result := make([]map[string]any, len(paths))
		for i, p := range paths {
			result[i] = map[string]any{"path": p.Path, "inode": p.Ino, "dev": p.Dev}
		}
		return jsonResult(result)
	})

	// add_protected_path
	srv.AddTool(mcp.NewTool("add_protected_path",
		mcp.WithDescription("Dynamically add a protected path"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path to protect")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var path string
		if args, ok := req.Params.Arguments.(map[string]any); ok {
			path, _ = args["path"].(string)
		}
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		if err := s.pathPolicy.AddPath(path); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Added protected path: %s", path)), nil
	})

	// remove_protected_path
	srv.AddTool(mcp.NewTool("remove_protected_path",
		mcp.WithDescription("Remove a protected path"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path to remove")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var path string
		if args, ok := req.Params.Arguments.(map[string]any); ok {
			path, _ = args["path"].(string)
		}
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		if removed := s.pathPolicy.RemovePath(path); !removed {
			return mcp.NewToolResultError(fmt.Sprintf("path %q not found in protected list", path)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Removed protected path: %s", path)), nil
	})

	// list_monitored_users
	srv.AddTool(mcp.NewTool("list_monitored_users",
		mcp.WithDescription("List currently monitored users"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.uidPolicy.Enabled() {
			return mcp.NewToolResultText("All users are monitored (no uid filter)"), nil
		}
		uids := s.uidPolicy.UIDs()
		result := make([]map[string]any, 0, len(uids))
		for uid, name := range uids {
			result = append(result, map[string]any{"uid": uid, "username": name})
		}
		return jsonResult(result)
	})

	// add_monitored_user
	srv.AddTool(mcp.NewTool("add_monitored_user",
		mcp.WithDescription("Add a user to the monitored list"),
		mcp.WithString("username", mcp.Required(), mcp.Description("System username to monitor")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var username string
		if args, ok := req.Params.Arguments.(map[string]any); ok {
			username, _ = args["username"].(string)
		}
		if username == "" {
			return mcp.NewToolResultError("username is required"), nil
		}
		if err := s.uidPolicy.AddUser(username); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Now monitoring user: %s", username)), nil
	})

	// get_recent_events
	srv.AddTool(mcp.NewTool("get_recent_events",
		mcp.WithDescription("Get recent interception events"),
		mcp.WithNumber("limit", mcp.Description("Max number of events to return (default 20)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit := 20
		if args, ok := req.Params.Arguments.(map[string]any); ok {
			if l, ok := args["limit"].(float64); ok && l > 0 {
				limit = int(l)
			}
		}
		s.mu.RLock()
		events := s.events
		s.mu.RUnlock()
		if len(events) > limit {
			events = events[len(events)-limit:]
		}
		result := make([]map[string]any, len(events))
		for i, e := range events {
			result[i] = map[string]any{
				"timestamp": time.Unix(0, int64(e.Timestamp)).Format(time.RFC3339Nano),
				"pid":       e.PID,
				"uid":       e.UID,
				"operation": e.Operation.String(),
				"path":      e.Path,
				"dest_path": e.DestPath,
				"comm":      e.Comm,
				"inode":     e.Ino,
			}
		}
		return jsonResult(result)
	})

	// analyze_event
	srv.AddTool(mcp.NewTool("analyze_event",
		mcp.WithDescription("Analyze a specific event index with LLM"),
		mcp.WithNumber("index", mcp.Required(), mcp.Description("Event index (0-based from get_recent_events)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if s.analyzer == nil {
			return mcp.NewToolResultError("LLM analyzer is disabled"), nil
		}
		var idx float64
		var ok bool
		if args, okMap := req.Params.Arguments.(map[string]any); okMap {
			idx, ok = args["index"].(float64)
		}
		if !ok {
			return mcp.NewToolResultError("index is required"), nil
		}
		s.mu.RLock()
		events := s.events
		s.mu.RUnlock()
		i := int(idx)
		if i < 0 || i >= len(events) {
			return mcp.NewToolResultError(fmt.Sprintf("invalid index %d (have %d events)", i, len(events))), nil
		}
		result, err := s.analyzer.Analyze(ctx, events[i])
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return jsonResult(result)
	})
}

// jsonResult 将任意值序列化为 JSON 并返回 ToolResult
func jsonResult(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}
