package alaye

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

func TestWAFValidateZeroIsDisabled(t *testing.T) {
	var w WAF
	if err := w.Validate(); err != nil {
		t.Fatalf("zero-value WAF should validate as disabled: %v", err)
	}
}

func TestWAFValidateActiveRequiresDriver(t *testing.T) {
	w := WAF{Status: expect.Active}
	if err := w.Validate(); err == nil {
		t.Fatal("active WAF without a driver should fail validation")
	}
}
