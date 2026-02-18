package cache

import "github.com/olekukonko/ll"

type CloseFn func()

func Closer(it *Item) (CloseFn, bool) {
	if it == nil || it.Value == nil {
		return nil, false
	}

	if c, ok := it.Value.(interface{ Close() error }); ok {
		return func() { _ = c.Close() }, true
	}

	if c, ok := it.Value.(interface{ Close() }); ok {
		return func() { c.Close() }, true
	}

	return nil, false
}

func CloserDelete(_ string, it *Item) {
	fn, ok := Closer(it)
	if !ok {
		return
	}
	fn()
}

func CloserDeleteWithLogger(_ string, it *Item, logger *ll.Logger) {
	if it == nil || it.Value == nil {
		return
	}

	if c, ok := it.Value.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil && logger != nil {
			logger.Error(err)
		}
		return
	}

	if c, ok := it.Value.(interface{ Close() }); ok {
		c.Close()
	}
}
