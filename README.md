# AssetsWarden

基于 eBPF LSM 的文件资产保护守护进程。能在内核态高效拦截对受保护目录的删除和重命名操作，并在用户态提供基于 MCP 的管控与大模型（LLM）行为分析能力。

## 特性

- **内核级防御**: 通过 `inode_unlink`、`inode_rmdir` 和 `inode_rename` LSM Hook 在内核空间直接阻断风险操作。
- **动态用户过滤**: 支持配置特定的监控用户。
- **智能化分析**: 当发生被拦截的安全事件时，结合大模型（LLM）自动诊断其风险。
- **MCP 控制流**: 暴露标准 MCP API，支持动态添加/删除保护路径、用户，查看守护程序状态和近期拦截历史。

## 系统要求

- Linux Kernel 5.7+，LSM 中必须开启 `bpf` 支持。可以通过 `cat /sys/kernel/security/lsm` 确认。
- root 权限。

## 构建与运行

### 构建

```bash
make build
```

### 配置

修改或创建 `configs/default.yaml`，示例配置：

```yaml
protected_paths:
  - /workshop/PPProject

monitored_users:
  - s3            # 如果置空或不存在该配置，则会监控拦截所有用户

log_level: info

llm:
  enabled: true
  endpoint: "https://api.openai.com/v1/chat/completions"
  api_key_env: "ASSETWARDEN_LLM_API_KEY"
  model: "gpt-4o"

mcp:
  enabled: true
  transport: stdio
```

### 运行

启动需要超级管理员权限。

```bash
sudo ./bin/assetwarden --config configs/default.yaml
```

当程序启动后，MCP 服务端会在标准输入输出暴露，你可以通过兼容的客户端工具对接，动态修改保护策略。

## 测试策略防御

1. 确保将 `/workshop/PPProject` 添加进保护目录 `protected_paths`。
2. 运行 `assetwarden`：`sudo make run`
3. 尝试在目录下删除文件：
   ```bash
   rm /workshop/PPProject/critical_file.txt
   ```
4. 将会得到 `Operation not permitted` 的内核阻断，并且能在 `assetwarden` 的终端中看到相关事件的安全分析日志（若开启 LLM）。
