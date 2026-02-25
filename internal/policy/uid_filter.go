package policy

import (
	"context"
	"fmt"
	"os/user"
	"strconv"

	"assetwarden/internal/model"
)

// UIDFilterPolicy 只对受监控的 uid 发 Deny（其余 Allow）
// 注意：内核侧也有 uid 过滤，两边要保持一致
type UIDFilterPolicy struct {
	uids    map[uint32]string // uid -> username
	enabled bool              // false = 监控所有用户
}

// NewUIDFilterPolicy 创建 UID 过滤策略
// usernames 为空时监控所有用户
func NewUIDFilterPolicy(usernames []string) (*UIDFilterPolicy, error) {
	if len(usernames) == 0 {
		return &UIDFilterPolicy{enabled: false}, nil
	}

	uids := make(map[uint32]string, len(usernames))
	for _, name := range usernames {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("lookup user %q: %w", name, err)
		}
		uid64, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse uid for %q: %w", name, err)
		}
		uids[uint32(uid64)] = name
	}
	return &UIDFilterPolicy{uids: uids, enabled: true}, nil
}

// UIDs 返回受监控的 uid -> username 映射
func (f *UIDFilterPolicy) UIDs() map[uint32]string {
	result := make(map[uint32]string, len(f.uids))
	for k, v := range f.uids {
		result[k] = v
	}
	return result
}

// Enabled 返回是否启用了 uid 过滤
func (f *UIDFilterPolicy) Enabled() bool {
	return f.enabled
}

// AddUser 动态添加监控用户
func (f *UIDFilterPolicy) AddUser(username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w", username, err)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("parse uid for %q: %w", username, err)
	}
	if !f.enabled {
		f.uids = make(map[uint32]string)
		f.enabled = true
	}
	f.uids[uint32(uid64)] = username
	return nil
}

// Evaluate 检查 event.UID 是否在监控列表中
func (f *UIDFilterPolicy) Evaluate(_ context.Context, event model.SyscallEvent) (model.PolicyResult, error) {
	if !f.enabled {
		// 未设置 uid 过滤 → 所有用户都要拦截
		return model.PolicyResult{Decision: model.Deny, Reason: "all users monitored"}, nil
	}
	if name, ok := f.uids[event.UID]; ok {
		return model.PolicyResult{
			Decision: model.Deny,
			Reason:   fmt.Sprintf("uid %d (%s) is monitored", event.UID, name),
		}, nil
	}
	return model.PolicyResult{Decision: model.Allow}, nil
}
