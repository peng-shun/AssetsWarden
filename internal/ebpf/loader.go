package ebpf

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"assetwarden/internal/config"
	"assetwarden/internal/ebpf/bpf"
)

// EBPFManager 管理 eBPF 程序的生命周期
type EBPFManager struct {
	objs   bpf.WardenObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewEBPFManager 加载 eBPF 程序，初始化 maps，attach LSM hooks
func NewEBPFManager(cfg config.Config) (*EBPFManager, error) {
	// 1. 检测环境：LSM 是否包含 "bpf"
	if err := checkLSMEnvironment(); err != nil {
		return nil, err
	}

	// 2. 提升 rlimit（允许锁定足够内存给 eBPF maps）
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	// 3. 加载 eBPF 对象（编译后的字节码嵌入在二进制中）
	var objs bpf.WardenObjects
	if err := bpf.LoadWardenObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	mgr := &EBPFManager{objs: objs}

	// 4. 初始化 config_map：写入保护路径的 inode + dev
	if err := mgr.initConfigMap(cfg.ProtectedPaths); err != nil {
		mgr.Close()
		return nil, fmt.Errorf("init config_map: %w", err)
	}

	// 5. 初始化 uid_filter_map
	if err := mgr.initUIDFilterMap(cfg.MonitoredUsers); err != nil {
		mgr.Close()
		return nil, fmt.Errorf("init uid_filter_map: %w", err)
	}

	// 6. Attach LSM hooks
	lsmHooks := []struct {
		name string
		prog *ciliumebpf.Program
	}{
		{"inode_unlink", objs.WardenUnlink},
		{"inode_rmdir", objs.WardenRmdir},
		{"inode_rename", objs.WardenRename},
	}
	for _, h := range lsmHooks {
		l, err := link.AttachLSM(link.LSMOptions{Program: h.prog})
		if err != nil {
			mgr.Close()
			return nil, fmt.Errorf("attach LSM hook %s: %w", h.name, err)
		}
		mgr.links = append(mgr.links, l)
		slog.Info("attached LSM hook", "hook", h.name)
	}

	// 7. 创建 ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		mgr.Close()
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}
	mgr.reader = reader

	return mgr, nil
}

// RingbufReader 返回 ring buffer reader（给 EventReader 使用）
func (m *EBPFManager) RingbufReader() *ringbuf.Reader {
	return m.reader
}

// Close detach 所有 links，关闭所有资源
func (m *EBPFManager) Close() {
	if m.reader != nil {
		_ = m.reader.Close()
	}
	for _, l := range m.links {
		_ = l.Close()
	}
	m.objs.Close()
}

// initConfigMap 把保护路径的 inode 写入 config_map
// key = inode (u64), value = dev (u64)
func (m *EBPFManager) initConfigMap(paths []string) error {
	for _, p := range paths {
		var stat syscall.Stat_t
		if err := syscall.Stat(p, &stat); err != nil {
			return fmt.Errorf("stat %q: %w", p, err)
		}
		ino := stat.Ino
		dev := uint64(stat.Dev)
		if err := m.objs.ConfigMap.Put(&ino, &dev); err != nil {
			return fmt.Errorf("put inode %d for path %q: %w", ino, p, err)
		}
		slog.Info("protecting path", "path", p, "inode", ino, "dev", dev)
	}
	return nil
}

// initUIDFilterMap 把监控用户的 uid 写入 uid_filter_map
func (m *EBPFManager) initUIDFilterMap(usernames []string) error {
	if len(usernames) == 0 {
		// 不启用 uid 过滤：uid_filter_enabled 保持空（不写 key 0）
		slog.Info("uid filter disabled: monitoring all users")
		return nil
	}

	// 标记为启用
	key := uint32(0)
	val := uint8(1)
	if err := m.objs.UidFilterEnabled.Put(&key, &val); err != nil {
		return fmt.Errorf("enable uid filter: %w", err)
	}

	for _, name := range usernames {
		uid, err := lookupUID(name)
		if err != nil {
			return err
		}
		sentinel := uint8(1)
		if err := m.objs.UidFilterMap.Put(&uid, &sentinel); err != nil {
			return fmt.Errorf("put uid %d for user %q: %w", uid, name, err)
		}
		slog.Info("monitoring user", "user", name, "uid", uid)
	}
	return nil
}

// UpdateConfigMap 动态更新 config_map（用于 MCP 动态添加/移除保护路径）
func (m *EBPFManager) UpdateConfigMap(ino uint64, dev uint64, add bool) error {
	if add {
		return m.objs.ConfigMap.Put(&ino, &dev)
	}
	return m.objs.ConfigMap.Delete(&ino)
}

// checkLSMEnvironment 检测内核是否支持 BPF LSM
func checkLSMEnvironment() error {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("cannot read /sys/kernel/security/lsm: %w (is securityfs mounted?)", err)
	}
	lsmList := strings.TrimSpace(string(data))
	if !strings.Contains(lsmList, "bpf") {
		return fmt.Errorf(
			"BPF LSM not active. Active LSMs: %q\n"+
				"To enable, add 'lsm=...,bpf' to kernel boot parameters and reboot.",
			lsmList,
		)
	}
	return nil
}

// lookupUID 将用户名转换为 uid
func lookupUID(username string) (uint32, error) {
	// 避免引入 os/user 包的 CGO 依赖，直接读 /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, fmt.Errorf("read /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] == username {
			var uid uint32
			if _, err := fmt.Sscanf(fields[2], "%d", &uid); err != nil {
				return 0, fmt.Errorf("parse uid for %q: %w", username, err)
			}
			return uid, nil
		}
	}
	return 0, fmt.Errorf("user %q not found in /etc/passwd", username)
}
