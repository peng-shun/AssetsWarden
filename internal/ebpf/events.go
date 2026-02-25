package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"
	"assetwarden/internal/model"
)

// RawEvent 是从 ring buffer 读出的原始内核事件结构体
// 必须和 warden.c 里 struct warden_event 完全对应（字节对齐）
type RawEvent struct {
	Timestamp   uint64
	PID         uint32
	UID         uint32
	Op          uint8
	Pad         [3]uint8
	Ino         uint64
	Dev         uint64
	DirIno      uint64
	DestIno     uint64
	DestDirIno  uint64
	Comm        [16]byte
}

// EventReader 从 ring buffer 持续消费内核事件
type EventReader struct {
	reader *ringbuf.Reader
}

// NewEventReader 创建 EventReader
func NewEventReader(reader *ringbuf.Reader) *EventReader {
	return &EventReader{reader: reader}
}

// Read 启动后台 goroutine 持续读取事件，将解析好的 SyscallEvent 发送到返回的 channel。
// 当 ctx 取消时，goroutine 退出，channel 关闭。
func (er *EventReader) Read(ctx context.Context) <-chan model.SyscallEvent {
	ch := make(chan model.SyscallEvent, 256)

	go func() {
		defer close(ch)
		for {
			// 检查 ctx 是否已取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := er.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				slog.Warn("ringbuf read error", "err", err)
				continue
			}

			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				slog.Warn("parse event error", "err", err)
				continue
			}

			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

// Close 关闭底层 ring buffer reader
func (er *EventReader) Close() error {
	return er.reader.Close()
}

// parseRawEvent 将字节切片解析为 SyscallEvent
func parseRawEvent(data []byte) (model.SyscallEvent, error) {
	// RawEvent 的固定大小：8+4+4+1+3+8+8+8+8+8+16 = 76 字节
	const rawSize = 76
	if len(data) < rawSize {
		return model.SyscallEvent{}, fmt.Errorf("short event: %d bytes", len(data))
	}

	var raw RawEvent
	// 手工解析（确保与 C 结构体对齐一致）
	raw.Timestamp    = binary.LittleEndian.Uint64(data[0:8])
	raw.PID          = binary.LittleEndian.Uint32(data[8:12])
	raw.UID          = binary.LittleEndian.Uint32(data[12:16])
	raw.Op           = data[16]
	// data[17:19] = pad
	// 需要对齐到 8 字节边界：17+3pad=20=offset of Ino
	raw.Ino          = binary.LittleEndian.Uint64(data[20:28])
	raw.Dev          = binary.LittleEndian.Uint64(data[28:36])
	raw.DirIno       = binary.LittleEndian.Uint64(data[36:44])
	raw.DestIno      = binary.LittleEndian.Uint64(data[44:52])
	raw.DestDirIno   = binary.LittleEndian.Uint64(data[52:60])
	copy(raw.Comm[:], data[60:76])

	evt := model.SyscallEvent{
		Timestamp: raw.Timestamp,
		PID:       raw.PID,
		UID:       raw.UID,
		Operation: model.OpType(raw.Op),
		Ino:       raw.Ino,
		Dev:       raw.Dev,
		DirIno:    raw.DirIno,
		DestIno:   raw.DestIno,
		DestDirIno: raw.DestDirIno,
		Comm:      commToString(raw.Comm),
	}
	return evt, nil
}

// commToString 将以 null 结尾的字节数组转为 Go string
func commToString(comm [16]byte) string {
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm[:])
}
