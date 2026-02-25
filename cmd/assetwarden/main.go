package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"assetwarden/internal/config"
	"assetwarden/internal/daemon"
)

func main() {
	configPath := flag.String("config", "configs/default.yaml", "path to config file")
	flag.Parse()

	// 配置结构化日志
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	slog.Info("AssetsWarden starting", "config", *configPath)
	slog.Info("config loaded", "detail", cfg.String())

	// 启动守护进程
	if err := daemon.Run(cfg); err != nil {
		slog.Error("daemon error", "err", err)
		os.Exit(1)
	}
}
