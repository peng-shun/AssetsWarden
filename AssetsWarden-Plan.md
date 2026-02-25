# AssetsWarden — 实现计划

## 项目定位

基于 eBPF LSM 的文件资产保护守护进程。在内核层拦截对受保护路径的删除和重命名操作，用户态提供策略判断、LLM 分析和 MCP 管理接口。

## 环境要求

- Linux kernel 5.7+，`CONFIG_BPF_LSM=y`，启动参数 `lsm=` 列表包含 `bpf`
- Go 1.21+
- clang/llvm（编译 eBPF C 程序）
- 启动时检测以上条件，不满足则给出明确报错并退出

---

## 架构总览

```
┌─────────────────────────────────────────────────────┐
│                   用户态 (Go)                        │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ MCP      │  │ LLM      │  │ PolicyEngine      │  │
│  │ Server   │  │ Analyzer │  │ (interface)        │  │
│  └────┬─────┘  └────┬─────┘  │  ├─ PathMatch     │  │
│       │              │        │  ├─ UidFilter     │  │
│       │              │        │  └─ (Future:      │  │
│       │              │        │     FileLineage)  │  │
│       │              │        └────────┬──────────┘  │
│       │              │                 │              │
│       └──────────────┴─────────┬───────┘              │
│                                │                      │
│                     ┌──────────▼──────────┐           │
│                     │   EventLoop         │           │
│                     │   (ring buffer 消费) │           │
│                     └──────────┬──────────┘           │
│                                │                      │
├────────────────────────────────┼──────────────────────┤
│              内核态 (eBPF C)    │                      │
│                                │                      │
│  ┌─────────────┐  ┌───────────▼───────────┐          │
│  │ BPF Maps    │  │ LSM Hooks             │          │
│  │             │◄─┤  ├─ inode_unlink      │          │
│  │ - config    │  │  ├─ inode_rmdir       │          │
│  │ - uid_list  │  │  └─ inode_rename      │          │
│  │ - events    │  └───────────────────────┘          │
│  └─────────────┘                                     │
└─────────────────────────────────────────────────────┘
```

### 数据流

1. 进程调用 `unlinkat` / `rmdir` / `renameat2` → 触发 LSM hook
2. eBPF 程序在内核态做**快速判断**：路径前缀匹配 + uid 过滤
3. 匹配命中 → 返回 `-EPERM`，操作被拒绝
4. 同时通过 ring buffer 发送事件到用户态
5. 用户态 EventLoop 消费事件 → 经过 PolicyEngine → 记录日志 / 调用 LLM 分析
6. MCP Server 暴露查询和配置接口

### 关键设计决策

**为什么拦截在内核态完成，而不是等用户态判断？**

LSM hook 是同步的，必须立即返回 allow/deny。这意味着核心安全策略（路径匹配 + uid）必须在 eBPF 里完成。用户态的 LLM 分析是**审计层**，不参与实时拦截决策。这是正确的安全架构——硬拦截不依赖用户态进程存活。

**LLM 的角色是什么？**

事后分析 + 智能告警。收到拦截事件后，把操作上下文（用户、命令、路径、时间、最近操作历史）发给 LLM，生成人类可读的分析报告和告警信息。不参与 allow/deny 决策。

---

## 项目结构

```
AssetWarden/
├── cmd/
│   └── assetwarden/
│       └── main.go              # 入口：参数解析、启动守护进程
│
├── internal/
│   ├── daemon/
│   │   └── daemon.go            # 守护进程主循环：加载 eBPF、启动各组件
│   │
│   ├── ebpf/
│   │   ├── loader.go            # 加载 eBPF 程序、管理 maps
│   │   ├── events.go            # ring buffer 事件消费、事件结构体定义
│   │   └── bpf/                 # eBPF C 源码 + 生成的 Go 绑定
│   │       ├── warden.c         # 内核态 LSM hook 实现
│   │       └── gen.go           # //go:generate 指令 (bpf2go)
│   │
│   ├── policy/
│   │   ├── engine.go            # PolicyEngine 接口定义 + ChainedPolicy
│   │   ├── path_match.go        # 路径前缀匹配策略
│   │   └── uid_filter.go        # 用户过滤策略
│   │
│   ├── analyzer/
│   │   └── llm.go               # LLM 客户端：构造 prompt、解析响应
│   │
│   ├── mcp/
│   │   └── server.go            # MCP 服务端：暴露工具接口
│   │
│   └── model/
│       └── types.go             # 共享类型：SyscallEvent, Decision 等
│
├── configs/
│   └── default.yaml             # 默认配置：保护路径、监控用户、LLM endpoint
│
├── go.mod
├── go.sum
├── Makefile                     # build、generate、install 目标
└── README.md
```

---

## 核心类型定义

```go
// model/types.go

// SyscallEvent 是从内核发到用户态的事件
type SyscallEvent struct {
    Timestamp uint64
    PID       uint32
    UID       uint32
    Operation OpType   // UNLINK, RMDIR, RENAME
    Path      string   // 目标路径
    DestPath  string   // rename 的目标路径（仅 RENAME 时有值）
    Comm      [16]byte // 进程名
}

type OpType uint8
const (
    OpUnlink OpType = iota
    OpRmdir
    OpRename
)

type Decision uint8
const (
    Allow Decision = iota
    Deny
)

type PolicyResult struct {
    Decision Decision
    Reason   string
}
```

---

## 组件详细设计

### 1. eBPF 内核程序 (`bpf/warden.c`)

使用 cilium/ebpf 的 bpf2go 工具链。eBPF C 代码编译为字节码，bpf2go 生成 Go 绑定。

**Hook 的 LSM 接口：**

| LSM Hook | 覆盖的 syscall | 参数 |
|---|---|---|
| `inode_unlink` | unlink, unlinkat | dir inode + dentry |
| `inode_rmdir` | rmdir | dir inode + dentry |
| `inode_rename` | rename, renameat, renameat2 | old_dir + old_dentry + new_dir + new_dentry |

**eBPF Maps：**

| Map 名 | 类型 | 用途 |
|---|---|---|
| `config_map` | BPF_MAP_TYPE_HASH | 存储保护路径列表（key: 路径哈希, value: 路径字符串） |
| `uid_filter_map` | BPF_MAP_TYPE_HASH | 存储受监控 uid 列表（key: uid, value: 1） |
| `events` | BPF_MAP_TYPE_RINGBUF | 向用户态发送拦截事件 |

**内核态判断逻辑（伪代码）：**

```c
SEC("lsm/inode_unlink")
int BPF_PROG(warden_unlink, struct inode *dir, struct dentry *dentry) {
    // 1. 获取当前 uid
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // 2. 从 dentry 解析路径（通过 d_name + 向上遍历 d_parent）
    //    注意：eBPF 里完整路径解析有栈大小限制，
    //    实际实现需要逐级比较 dentry 名字

    // 3. 路径匹配：检查是否在保护目录下
    //    方案A: 比较 dentry 链上的目录名
    //    方案B: 比较 inode 所在 mount + 目录 inode number

    // 4. 命中 → 发送事件到 ring buffer + 返回 -EPERM
    // 5. 未命中 → 返回 0（放行）
}
```

**路径匹配的工程难点：**

eBPF 里不能调用 `d_path()`（它不是 BPF helper），需要手动遍历 `dentry->d_parent` 链拼出路径。栈大小限制 512 字节，所以路径长度有上限。实际实现中常用的方案是：

- 逐级比较 dentry name（从目标向上走，依次比较 `PPProject` → `workshop` → `/`）
- 或者在用户态预先查出保护目录的 inode number，在 eBPF 里直接比较 inode

**推荐方案：inode 比较。** 用户态启动时 `stat("/workshop/PPProject")` 拿到 device + inode，写入 `config_map`。内核态从 `dentry->d_inode` 取 inode number，向上遍历检查是否有祖先 inode 匹配保护目录。这比字符串比较更可靠、更快。

### 2. eBPF 加载器 (`internal/ebpf/`)

```go
// loader.go
type EBPFManager struct {
    objs    wardenObjects   // bpf2go 生成的对象
    links   []link.Link     // LSM attach 返回的 link
}

func NewEBPFManager(cfg Config) (*EBPFManager, error) {
    // 1. 检测环境：/sys/kernel/security/lsm 是否包含 "bpf"
    // 2. 加载 eBPF 对象
    // 3. 初始化 maps：写入保护路径的 inode、监控 uid
    // 4. Attach LSM hooks
    // 5. 返回 manager
}

func (m *EBPFManager) Close() {
    // detach + close，清理资源
}
```

```go
// events.go
type EventReader struct {
    reader *ringbuf.Reader
}

func (r *EventReader) Read(ctx context.Context) <-chan model.SyscallEvent {
    // 持续从 ring buffer 读取事件，解析为 Go struct，发到 channel
}
```

### 3. 策略引擎 (`internal/policy/`)

```go
// engine.go
type PolicyEngine interface {
    Evaluate(ctx context.Context, event model.SyscallEvent) (model.PolicyResult, error)
}

// ChainedPolicy 按顺序执行多个策略，第一个返回 Deny 的生效
type ChainedPolicy struct {
    policies []PolicyEngine
}

func (c *ChainedPolicy) Evaluate(ctx context.Context, event model.SyscallEvent) (model.PolicyResult, error) {
    for _, p := range c.policies {
        result, err := p.Evaluate(ctx, event)
        if err != nil {
            return model.PolicyResult{Decision: model.Deny, Reason: "policy error"}, err
        }
        if result.Decision == model.Deny {
            return result, nil
        }
    }
    return model.PolicyResult{Decision: model.Allow}, nil
}
```

注意：当前的实际拦截发生在内核态。用户态的 PolicyEngine 主要用于：
- 事后审计判断（和内核决策应一致）
- 为 LLM 分析提供结构化输入
- 未来扩展（如 FileLineage 策略需要用户态状态）

### 4. LLM 分析器 (`internal/analyzer/`)

```go
// llm.go
type LLMAnalyzer struct {
    endpoint string
    apiKey   string
    client   *http.Client
}

type AnalysisResult struct {
    RiskLevel   string // "critical" / "warning" / "info"
    Explanation string // 人类可读的分析
    Suggestion  string // 建议的响应动作
}

func (a *LLMAnalyzer) Analyze(ctx context.Context, event model.SyscallEvent) (*AnalysisResult, error) {
    // 1. 构造 prompt：
    //    - 操作类型、路径、用户
    //    - 进程名（comm）
    //    - （未来）最近操作历史
    // 2. 调用 LLM API
    // 3. 解析响应为 AnalysisResult
}
```

**Prompt 设计要点：**

让 LLM 扮演安全审计员角色，给出操作的风险评估。输入是结构化的 JSON 事件，输出要求结构化（JSON 或固定格式）。这一层是纯审计，不影响拦截决策。

### 5. MCP Server (`internal/mcp/`)

暴露以下工具接口：

| Tool | 功能 | 参数 |
|---|---|---|
| `get_status` | 查询守护进程状态 | 无 |
| `list_protected_paths` | 列出当前保护的路径 | 无 |
| `add_protected_path` | 动态添加保护路径 | path: string |
| `remove_protected_path` | 移除保护路径 | path: string |
| `list_monitored_users` | 列出受监控用户 | 无 |
| `add_monitored_user` | 添加监控用户 | username: string |
| `get_recent_events` | 查询最近的拦截事件 | limit: int |
| `analyze_event` | 对指定事件调用 LLM 分析 | event_id: string |

MCP 服务端通过 stdio 或 SSE 通信，供 Claude 等 AI 工具直接调用。

### 6. 守护进程主循环 (`internal/daemon/`)

```go
func Run(cfg Config) error {
    // 1. 检测环境
    // 2. 解析配置：保护路径 → stat 获取 inode，用户名 → 查 uid
    // 3. 加载 eBPF 程序、初始化 maps
    // 4. 启动 event reader goroutine
    // 5. 启动 MCP server goroutine
    // 6. 主循环：消费事件 channel
    //    - 记录日志
    //    - 调用 PolicyEngine（审计一致性）
    //    - 异步调用 LLM 分析
    //    - 通过 MCP 推送告警
    // 7. 优雅退出：signal handler → detach eBPF → close maps
}
```

---

## 配置文件

```yaml
# configs/default.yaml
protected_paths:
  - /workshop/PPProject

monitored_users:
  - s3            # 不指定则监控所有用户

log_level: info

llm:
  enabled: false  # 默认关闭，需要显式开启
  endpoint: "https://api.example.com/v1/chat/completions"
  api_key_env: "ASSETWARDEN_LLM_API_KEY"  # 从环境变量读取
  model: "claude-sonnet-4-20250514"

mcp:
  enabled: true
  transport: stdio  # stdio | sse
```

---

## 构建与运行

```makefile
# Makefile

.PHONY: generate build install

generate:
	cd internal/ebpf/bpf && go generate ./...

build: generate
	go build -o bin/assetwarden ./cmd/assetwarden

install: build
	sudo cp bin/assetwarden /usr/local/bin/

run: build
	sudo ./bin/assetwarden --config configs/default.yaml
```

**bpf2go 生成指令（gen.go）：**

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" warden warden.c
```

---

## 实现顺序建议

### Phase 1：最小可用版本

1. 写 `warden.c`，实现 `inode_unlink` 的 LSM hook，硬编码一个 inode 比较
2. Go 侧用 bpf2go 生成绑定，加载并 attach
3. 验证：`rm /workshop/PPProject/testfile` 被拒绝，返回 "Operation not permitted"
4. 添加 ring buffer 事件，Go 侧打印拦截日志

### Phase 2：完整拦截

5. 添加 `inode_rmdir` 和 `inode_rename` hook
6. 实现 uid 过滤（从配置读用户名 → 转 uid → 写入 map）
7. 实现配置文件解析，支持多个保护路径

### Phase 3：LLM 与 MCP

8. 实现 LLM analyzer，接入 API
9. 实现 MCP server，暴露管理接口
10. 事件驱动：拦截事件 → 异步 LLM 分析 → MCP 推送

### Phase 4：打磨

11. 优雅退出、错误处理
12. 启动时环境检测 + 友好报错
13. README、使用文档

---

## 已知难点与应对

| 难点 | 描述 | 应对方案 |
|---|---|---|
| eBPF 路径解析 | 内核态无法调用 `d_path()`，需手动遍历 dentry | 用 inode 比较替代字符串比较 |
| 栈大小限制 | eBPF 栈只有 512 字节 | 减少局部变量，用 per-cpu array map 做临时缓冲 |
| dentry 遍历深度 | verifier 要求有界循环 | `#pragma unroll` 或 `bpf_loop()`（5.17+，你的内核支持） |
| bpf2go 交叉编译 | ARM 上编译 eBPF 需要正确的 target | bpf2go 默认 target 是 bpf，与宿主架构无关 |
| LSM hook 参数访问 | 需要 BTF，通过 `BPF_PROG` 宏访问 | 你的内核有 BTF（OrbStack 6.17） |

---

## 未来扩展接口

### FileLineage（文件血缘追踪）

`PolicyEngine` 接口已经预留。未来实现 `FileLineagePolicy` 时：

- 在 `SyscallEvent` 中使用已有的 `UID`、`Path`、`DestPath` 字段
- 额外字段（如需要）：在 ring buffer 事件结构体中加入 `Ino uint64` 和 `Dev uint64`
- 用户态维护 `map[InodeKey]OriginalPath` 追踪表
- rename 事件 → 更新表
- unlink 事件 → 查表，如果 inode 最终来源于保护目录 → 报告

不需要改内核程序，只需在用户态消费同一个 ring buffer 的事件流。
