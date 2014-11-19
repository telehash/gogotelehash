package netwatch

import (
	"testing"
	"time"

	"github.com/telehash/gogotelehash/e3x"
)

func TestModule(t *testing.T) {
	e, err := e3x.Open(Module(), e3x.Log(nil))
	if err != nil {
		t.Fatal(err)
	}

	defer e.Stop()

	time.Sleep(5 * time.Second)
}
