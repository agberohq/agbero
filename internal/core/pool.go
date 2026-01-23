package core

import "sync"

// 32KB buffer size (standard for io.Copy)
const bufferSize = 32 * 1024

type BufferPool struct {
	pool sync.Pool
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				// We create a slice of specific size
				b := make([]byte, bufferSize)
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
	if len(x) == bufferSize {
		b.pool.Put(&x)
	}
}
