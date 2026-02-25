package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"assetwarden/internal/analyzer"
	"assetwarden/internal/config"
	ebpfpkg "assetwarden/internal/ebpf"
	mcpserver "assetwarden/internal/mcp"
	"assetwarden/internal/model"
	"assetwarden/internal/policy"
)

// Run 启动 AssetsWarden 守护进程
// 这是程序的主循环，负责协调所有子系统
func Run(cfg config.Config) error {
	// --- 1. 初始化用户态策略引擎 ---
	pathPolicy, err := policy.NewPathMatchPolicy(cfg.ProtectedPaths)
	if err != nil {
		return fmt.Errorf("init path policy: %w", err)
	}

	uidPolicy, err := policy.NewUIDFilterPolicy(cfg.MonitoredUsers)
	if err != nil {
		return fmt.Errorf("init uid policy: %w", err)
	}

	engine := policy.NewChainedPolicy(uidPolicy, pathPolicy)

	// --- 2. 初始化 LLM 分析器（可选）---
	var llmAnalyzer *analyzer.LLMAnalyzer
	if cfg.LLM.Enabled {
		llmAnalyzer = analyzer.NewLLMAnalyzer(cfg.LLM)
		slog.Info("LLM analyzer enabled", "endpoint", cfg.LLM.Endpoint, "model", cfg.LLM.Model)
	} else {
		slog.Info("LLM analyzer disabled")
	}

	// --- 3. 加载 eBPF 程序 ---
	slog.Info("loading eBPF program...")
	mgr, err := ebpfpkg.NewEBPFManager(cfg)
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	defer func() {
		slog.Info("detaching eBPF hooks...")
		mgr.Close()
	}()
	slog.Info("eBPF hooks attached successfully")

	// --- 4. 启动 event reader ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventReader := ebpfpkg.NewEventReader(mgr.RingbufReader())
	eventCh := eventReader.Read(ctx)

	// --- 5. 初始化 MCP server ---
	mcpSrv := mcpserver.NewServer(pathPolicy, uidPolicy, llmAnalyzer)

	var wg sync.WaitGroup

	if cfg.MCP.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("starting MCP server", "transport", cfg.MCP.Transport)
			if err := mcpSrv.ServeStdio(ctx); err != nil {
				slog.Error("MCP server error", "err", err)
			}
		}()
	}

	// --- 6. 信号处理 ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	slog.Info("AssetsWarden started", "protected_paths", cfg.ProtectedPaths)
	slog.Info("press Ctrl+C to stop")

	// --- 7. 主事件循环 ---
	for {
		select {
		case evt, ok := <-eventCh:
			if !ok {
				slog.Info("event channel closed, exiting")
				cancel()
				wg.Wait()
				return nil
			}
			handleEvent(ctx, evt, engine, llmAnalyzer, mcpSrv, pathPolicy)

		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			cancel()
			wg.Wait()
			return nil
		}
	}
}

// handleEvent 处理单个拦截事件
func handleEvent(
	ctx context.Context,
	evt model.SyscallEvent,
	engine policy.PolicyEngine,
	llmAnalyzer *analyzer.LLMAnalyzer,
	mcpSrv *mcpserver.Server,
	pathPolicy *policy.PathMatchPolicy,
) {
	// 尝试从 inode 信息还原路径（尽力而为）
	protected := pathPolicy.Protected()
	evt.Path = policy.ResolveEventPath(evt, protected)

	ts := time.Unix(0, int64(evt.Timestamp))

	// 记录拦截日志
	slog.Warn("INTERCEPTED",
		"time", ts.Format(time.RFC3339),
		"op", evt.Operation.String(),
		"pid", evt.PID,
		"uid", evt.UID,
		"comm", evt.Comm,
		"path", evt.Path,
		"dest_path", evt.DestPath,
		"inode", evt.Ino,
	)

	// 用户态策略引擎审计（与内核决策保持一致性）
	result, err := engine.Evaluate(ctx, evt)
	if err != nil {
		slog.Error("policy evaluate error", "err", err)
	} else if result.Decision == model.Allow {
		// 理论上不应出现：内核拒绝了，用户态却 Allow
		slog.Warn("policy inconsistency: kernel denied but userspace allows",
			"reason", result.Reason)
	}

	// 记录到 MCP 事件历史
	mcpSrv.RecordEvent(evt)

	// 异步 LLM 分析（不阻塞主循环）
	if llmAnalyzer != nil {
		go func(e model.SyscallEvent) {
			analysisCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			analysis, err := llmAnalyzer.Analyze(analysisCtx, e)
			if err != nil {
				slog.Warn("LLM analysis failed", "err", err)
				return
			}
			slog.Info("LLM analysis",
				"risk_level", analysis.RiskLevel,
				"explanation", analysis.Explanation,
				"suggestion", analysis.Suggestion,
			)
		}(evt)
	}
}
