package errfmt

import (
	"errors"
	"testing"
)

func TestOneLine(t *testing.T) {
	err := errors.New("yaml: unmarshal errors:\n  line 2: field foo not found\n\tline 3:  bad")
	if got, want := OneLine(err), "yaml: unmarshal errors: line 2: field foo not found line 3: bad"; got != want {
		t.Errorf("OneLine = %q, want %q", got, want)
	}
}
