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
				// We create a slice of specific size
				b := make([]byte, woos.BufferSize)
				return &b
			},
		},
	}
}

func (b *BufferPool) Get() []byte {
	ptr := b.pool.Get().(*[]byte)
	return *ptr // Return the slice
}

func (b *BufferPool) Put(x []byte) {
	// Only put back if it's the right size (sanity check)
	if len(x) == woos.BufferSize {
		b.pool.Put(&x)
	}
}
