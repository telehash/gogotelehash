package hashname

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	h, err := FromIntermediates(map[string]string{
		"1a": "m5de45cchffxgzlsivegcmdbhb4xm43rintdatjslbtui3kmkzha",
		"2a": "ja3xsm3fgjnfgu3ylfbdos3ei5bwoocpmj4vcqtdgf2diqrtgi4a",
	})
	assert.NoError(err)
	assert.Equal("a3e6830ka5bgu6e4u6veykc2zqn8c42f4cnj7jxb2qe4zbgj1g00", h)

	h, err = FromIntermediates(map[string]string{
		"1a": "m5de45cchfzxgzlsivegcmdbhb4xm43rintdatjslbtui3kmkzha",
		"2a": "ja3xsm3fgjzfgu3ylfbdos3ei5bwoocpmj4vcqtdgf2diqrtgi4a",
	})
	assert.NoError(err)
	assert.Equal("59n8gkhau0gguqaakv5vmw2nhy12y2r09f2phw97ec5pbdhrvy0g", h)

	h, err = FromIntermediates(map[string]string{
		"1a": "gmamb66xcujtuzu9cm3ea9jjwxeyn2c0r8a4bz8y7b7n408bz630",
		"2a": "5vt3teqvjettaxkzkh47a7ta48e3hgp3bruern92xgh89am04h4g",
	})
	assert.NoError(err)
	assert.Equal("hryr6300r82pcrbbqud3jbcw8q9jyy4t3946c1n7d4t50269jaq0", h)

	h, err = FromKeyAndIntermediates(
		"3a",
		mustHex("cf9af94e2d2eff9000d9257e5817f9ed35398cbc8e7063073e1e11d403c43636"),
		map[string]string{
			"1a": "kbr7mf0fgz04fd0tjtntxpx4pk9ht4qryk647mvy9gn39upu7zcg",
		})
	assert.NoError(err)
	assert.Equal("5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g", h)

	h, err = FromKeys(map[string]string{
		"3a": "tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
		"2a": "621028hg1m30jam6923fe381040ga003g80gy01gg80gm0m2040g1c7bn5rdbmctf9qf56xvjf7d0faygd350fgpwy9baqg9e6ffhmmd2z0dytj6m6yn4cud1ny2nbv4qt7mn0fcper50zv4g1kavyv7mxm4tc06xhq33n8mzn80c6y6knyntvxfcnh1k9aftvrrb43b3vrh7eed3h117z4rqcruj3c38nyj6mdaudgdz6eph2wb2zzjf9h1c0tz9np4nbpvj42m5k192gqb36cgzvhchmzr3d4xutv3knw31h9g28bfbaawdexzrtc1cjdpx7yz6x9v2wjjhhettq1ehm457vf1r1kuqmynyvfkr5hhv3vf3dmwqxh03kruk0y2zve3h39a9d748raemkjg02avxcm3ktrd1jaxnbcup69m1u0e9kuq3mffj0g0cq3rqyjqyr2491820c0g008",
		"1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun",
	})
	assert.NoError(err)
	assert.Equal("rgcnnd04way28xzr0zthqqzaz6yr5vqbjx6ub6fg4npxmkkcp6a0", h)

	h, err = FromKeys(map[string]string{
		"3a": "tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
		"1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun",
	})
	assert.NoError(err)
	assert.Equal("5ccn9gcxnj9nd7hp1m3v5pjwcu5hq80bt366bzh1ebhf9zqaxu2g", h)

	h, err = FromKeys(map[string]string{
		"1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun",
	})
	assert.NoError(err)
	assert.Equal("5bx4502uhjcp6xymjpzp6ku9ehh29j3zw9vr6u6rh26btu75cw4g", h)
}

func mustHex(s string) []byte {
	d, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return d
}
