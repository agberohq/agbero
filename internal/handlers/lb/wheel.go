package lb

import "git.imaxinacion.net/aibox/agbero/internal/handlers/xhttp"

type weightWheel struct {
	cumul []uint64
	total uint64
}

func buildWheel(list []*xhttp.Backend) *weightWheel {
	if len(list) == 0 {
		return &weightWheel{}
	}
	cumul := make([]uint64, len(list))
	var sum uint64
	allOne := true

	for i, b := range list {
		w := uint64(1)
		if b != nil && b.Weight > 0 {
			w = uint64(b.Weight)
		}
		if w != 1 {
			allOne = false
		}
		sum += w
		cumul[i] = sum
	}

	if allOne {
		return &weightWheel{total: sum, cumul: nil}
	}
	return &weightWheel{cumul: cumul, total: sum}
}

func (w *weightWheel) next(counter uint64) int {
	if w == nil || w.total == 0 {
		return 0
	}
	if len(w.cumul) == 0 {
		return int(counter % w.total)
	}
	target := counter % w.total
	return w.search(target)
}

func (w *weightWheel) search(target uint64) int {
	if len(w.cumul) == 0 {
		return int(target)
	}

	i, j := 0, len(w.cumul)
	for i < j {
		h := int(uint(i+j) >> 1)
		if w.cumul[h] <= target {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= len(w.cumul) {
		return len(w.cumul) - 1
	}
	return i
}
