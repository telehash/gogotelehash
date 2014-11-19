package uri

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"

	_ "github.com/telehash/gogotelehash/e3x"
)

func Test_resolveDNS(t *testing.T) {
	// When using boot2docker run:
	//   boot2docker stop
	//   VBoxManage modifyvm "boot2docker-vm" --natdnshostresolver1 off
	//   VBoxManage modifyvm "boot2docker-vm" --natdnsproxy1 on
	//   boot2docker start

	assert := assert.New(t)

	uri, err := Parse("01.test.simonmenke.me")
	if err != nil {
		panic(err)
	}

	ident, err := resolveSRV(uri, "udp")
	if assert.NoError(err) && assert.NotNil(ident) {
		t.Logf("ident=%v addrs=%v keys=%v", ident, ident.Addresses(), ident.Keys())
	}
}
