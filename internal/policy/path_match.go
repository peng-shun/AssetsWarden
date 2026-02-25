package policy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"assetwarden/internal/model"
)

// ProtectedPath 是单条保护路径的信息
type ProtectedPath struct {
	Path string
	Ino  uint64 // inode number（由 stat 获取）
	Dev  uint64 // 设备号
}

// PathMatchPolicy 根据 inode 判断事件是否命中受保护路径
// 与内核侧使用完全相同的逻辑，用于用户态审计
type PathMatchPolicy struct {
	protected []ProtectedPath
}

// NewPathMatchPolicy 创建路径匹配策略
// paths 是原始路径字符串列表，会自动 stat 获取 inode
func NewPathMatchPolicy(paths []string) (*PathMatchPolicy, error) {
	protected := make([]ProtectedPath, 0, len(paths))
	for _, p := range paths {
		var stat syscall.Stat_t
		if err := syscall.Stat(p, &stat); err != nil {
			return nil, fmt.Errorf("stat protected path %q: %w", p, err)
		}
		protected = append(protected, ProtectedPath{
			Path: p,
			Ino:  stat.Ino,
			Dev:  uint64(stat.Dev),
		})
	}
	return &PathMatchPolicy{protected: protected}, nil
}

// Protected 返回保护路径信息列表（供 MCP 查询用）
func (p *PathMatchPolicy) Protected() []ProtectedPath {
	result := make([]ProtectedPath, len(p.protected))
	copy(result, p.protected)
	return result
}

// AddPath 动态添加保护路径
func (p *PathMatchPolicy) AddPath(path string) error {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return fmt.Errorf("stat path %q: %w", path, err)
	}
	p.protected = append(p.protected, ProtectedPath{
		Path: path,
		Ino:  stat.Ino,
		Dev:  uint64(stat.Dev),
	})
	return nil
}

// RemovePath 动态移除保护路径
func (p *PathMatchPolicy) RemovePath(path string) bool {
	for i, pp := range p.protected {
		if pp.Path == path {
			p.protected = append(p.protected[:i], p.protected[i+1:]...)
			return true
		}
	}
	return false
}

// Evaluate 检查事件的 dir_ino/dev 是否匹配受保护目录
func (p *PathMatchPolicy) Evaluate(_ context.Context, event model.SyscallEvent) (model.PolicyResult, error) {
	for _, pp := range p.protected {
		if event.Dev == pp.Dev && (event.DirIno == pp.Ino || event.Ino == pp.Ino) {
			return model.PolicyResult{
				Decision: model.Deny,
				Reason:   fmt.Sprintf("path matches protected directory %q", pp.Path),
			}, nil
		}
	}
	return model.PolicyResult{Decision: model.Allow}, nil
}

// ResolveEventPath 尝试从 inode 信息还原路径（尽力而为）
// 主要用于日志记录，不保证完全准确
func ResolveEventPath(event model.SyscallEvent, protected []ProtectedPath) string {
	for _, pp := range protected {
		if event.Dev == pp.Dev {
			if event.DirIno == pp.Ino {
				return pp.Path + "/<file>"
			}
			if event.Ino == pp.Ino {
				return pp.Path
			}
		}
	}
	// fallback: 用 /proc/self/fd 等方式尝试解析（此处简化）
	return resolveFromProc(event.Ino)
}

// resolveFromProc 尝试从 /proc 文件系统还原路径（尽力而为）
func resolveFromProc(ino uint64) string {
	// 扫描 /proc/*/fd/* 找到对应 inode 的符号链接目标
	// 简化实现：只扫描有限数量的 fd
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Sprintf("<inode:%d>", ino)
	}
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		fdDir := "/proc/" + p.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link := fdDir + "/" + fd.Name()
			var stat syscall.Stat_t
			if err := syscall.Stat(link, &stat); err == nil && stat.Ino == ino {
				target, err := os.Readlink(link)
				if err == nil && !strings.HasPrefix(target, "socket:") {
					return target
				}
			}
		}
	}
	return fmt.Sprintf("<inode:%d>", ino)
}
