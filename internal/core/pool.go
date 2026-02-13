package core

import (
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

type BufferPool struct {
	pool sync.Pool
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, woos.BufferSize)
				return &b
			},
		},
	}
}

func (b *BufferPool) Get() []byte {
	ptr := b.pool.Get().(*[]byte)
	// Reslice to full capacity to ensure we give out a usable buffer
	// even if the previous user sliced it down.
	return (*ptr)[:cap(*ptr)]
}

func (b *BufferPool) Put(x []byte) {
	// io.Copy often returns a slice (e.g. x[:n]), but we want to reuse the underlying array.
	if cap(x) >= woos.BufferSize {
		b.pool.Put(&x)
	}
}
