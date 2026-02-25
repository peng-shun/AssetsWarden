package model

// SyscallEvent 是从内核发到用户态的事件
type SyscallEvent struct {
	Timestamp uint64
	PID       uint32
	UID       uint32
	Operation OpType // UNLINK, RMDIR, RENAME
	Path      string // 目标路径（由用户态从内核事件重建）
	Comm      string // 进程名（来自内核 comm 字段）

	// eBPF 内核发送的原始 inode 信息
	Ino    uint64 // 目标文件 inode
	Dev    uint64 // 目标文件所在设备
	DirIno uint64 // 父目录 inode（用于路径匹配）

	// rename 专用
	DestPath   string // rename 的目标路径
	DestIno    uint64 // rename 目标 inode
	DestDirIno uint64 // rename 目标父目录 inode
}

// OpType 操作类型
type OpType uint8

const (
	OpUnlink OpType = iota // unlink / unlinkat
	OpRmdir                // rmdir
	OpRename               // rename, renameat, renameat2
)

func (o OpType) String() string {
	switch o {
	case OpUnlink:
		return "UNLINK"
	case OpRmdir:
		return "RMDIR"
	case OpRename:
		return "RENAME"
	default:
		return "UNKNOWN"
	}
}

// Decision 策略裁决
type Decision uint8

const (
	Allow Decision = iota
	Deny
)

// PolicyResult 策略引擎的裁决结果
type PolicyResult struct {
	Decision Decision
	Reason   string
}
