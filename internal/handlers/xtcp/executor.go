package xtcp

import (
	"bytes"
	"context"
	"time"
)

type TCPExecutor struct {
	Pool   *connPool
	Send   []byte
	Expect []byte
}

func (t *TCPExecutor) Probe(ctx context.Context) (bool, time.Duration, error) {
	start := time.Now()
	pc, err := t.Pool.get(ctx)
	if err != nil {
		return false, time.Since(start), err
	}
	defer t.Pool.put(pc)

	conn := pc.Conn
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	if len(t.Send) > 0 {
		if _, err := conn.Write(t.Send); err != nil {
			pc.failed.Store(true)
			return false, time.Since(start), err
		}
	}

	if len(t.Expect) > 0 {
		buf := getCheckBuf()
		defer putCheckBuf(buf)
		n, err := conn.Read(buf)
		if err != nil {
			pc.failed.Store(true)
			return false, time.Since(start), err
		}
		if !bytes.Contains(buf[:n], t.Expect) {
			return false, time.Since(start), nil
		}
	}

	return true, time.Since(start), nil
}
