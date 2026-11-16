package security

import "testing"

func TestPasswordGenerateLengths(t *testing.T) {
	for _, n := range []int{0, 1, 32, 64} {
		got, err := NewPassword().Generate(n)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		want := n
		if want <= 0 {
			want = 32
		}
		if len(got) != want {
			t.Fatalf("length %d: got %d bytes", n, len(got))
		}
	}
}
