package zulu

import (
	"sync"

	"github.com/agberohq/agbero/internal/core/def"
)

type BufferPool struct {
	pool sync.Pool
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, def.BufferSize)
			},
		},
	}
}

func (b *BufferPool) Get() []byte {
	x := b.pool.Get().([]byte)
	return x[:cap(x)]
}

func (b *BufferPool) Put(x []byte) {
	if cap(x) >= def.BufferSize {
		b.pool.Put(x)
	}
}
