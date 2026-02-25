package policy

import (
	"context"
	"fmt"

	"assetwarden/internal/model"
)

// PolicyEngine 是策略引擎的接口
// 注意：实际的内核拦截发生在 eBPF 侧，此接口用于用户态的审计和一致性校验
type PolicyEngine interface {
	Evaluate(ctx context.Context, event model.SyscallEvent) (model.PolicyResult, error)
}

// ChainedPolicy 按顺序执行多个策略，第一个返回 Deny 的生效
type ChainedPolicy struct {
	policies []PolicyEngine
}

// NewChainedPolicy 创建 ChainedPolicy
func NewChainedPolicy(policies ...PolicyEngine) *ChainedPolicy {
	return &ChainedPolicy{policies: policies}
}

// Evaluate 依次执行所有策略，第一个 Deny 立即返回
func (c *ChainedPolicy) Evaluate(ctx context.Context, event model.SyscallEvent) (model.PolicyResult, error) {
	for _, p := range c.policies {
		result, err := p.Evaluate(ctx, event)
		if err != nil {
			return model.PolicyResult{
				Decision: model.Deny,
				Reason:   fmt.Sprintf("policy error: %v", err),
			}, err
		}
		if result.Decision == model.Deny {
			return result, nil
		}
	}
	return model.PolicyResult{Decision: model.Allow, Reason: "no policy matched"}, nil
}
