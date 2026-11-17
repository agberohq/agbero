package xhttp

import (
	"net/http/httptest"
	"testing"
)

func TestHedgeWriterDiscardsLateLoserAfterClose(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &basicStatusWriter{ResponseWriter: rec}
	state := &hedgeState{}
	winner := &hedgeWriter{ResponseWriter: sw, state: state, id: 1}
	loser := &hedgeWriter{ResponseWriter: sw, state: state, id: 2}

	if _, err := winner.Write([]byte("winner")); err != nil {
		t.Fatal(err)
	}
	state.close()

	// Simulate a late loser after the winner's handler returned and the
	// shared basicStatusWriter was released.
	sw.ResponseWriter = nil
	if n, err := loser.Write([]byte("late-loser")); err != nil || n != len("late-loser") {
		t.Fatalf("late loser write = %d, %v", n, err)
	}
	if got := rec.Body.String(); got != "winner" {
		t.Fatalf("body = %q, want winner", got)
	}
}
