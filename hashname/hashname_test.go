package hashname

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCoding(t *testing.T) {
	assert := assert.New(t)

	h, err := FromIntermediates(map[string]string{
		"1a": "m5de45cchffxgzlsivegcmdbhb4xm43rintdatjslbtui3kmkzha",
		"2a": "ja3xsm3fgjnfgu3ylfbdos3ei5bwoocpmj4vcqtdgf2diqrtgi4a",
	})
	assert.NoError(err)
	assert.Equal("fbmscmngpdws3srjk3burinirenuepg25ayvrk53v5tks6cw33ea", h)

	h, err = FromIntermediates(map[string]string{
		"1a": "m5de45cchfzxgzlsivegcmdbhb4xm43rintdatjslbtui3kmkzha",
		"2a": "ja3xsm3fgjzfgu3ylfbdos3ei5bwoocpmj4vcqtdgf2diqrtgi4a",
	})
	assert.NoError(err)
	assert.Equal("nofu4jdoabl26vkk4yort5iaxni2bs5wa7uk75q5t75caqfptrpa", h)

	// h, err = FromKeys(map[string]string{
	//   "3a": "tydfjkhd5vzt006t4nz5g5ztxmukk35whtr661ty3r8x80y46rv0",
	//   "2a": "621028hg1m30jam6923fe381040ga003g80gy01gg80gm0m2040g1c7bn5rdbmctf9qf56xvjf7d0faygd350fgpwy9baqg9e6ffhmmd2z0dytj6m6yn4cud1ny2nbv4qt7mn0fcper50zv4g1kavyv7mxm4tc06xhq33n8mzn80c6y6knyntvxfcnh1k9aftvrrb43b3vrh7eed3h117z4rqcruj3c38nyj6mdaudgdz6eph2wb2zzjf9h1c0tz9np4nbpvj42m5k192gqb36cgzvhchmzr3d4xutv3knw31h9g28bfbaawdexzrtc1cjdpx7yz6x9v2wjjhhettq1ehm457vf1r1kuqmynyvfkr5hhv3vf3dmwqxh03kruk0y2zve3h39a9d748raemkjg02avxcm3ktrd1jaxnbcup69m1u0e9kuq3mffj0g0cq3rqyjqyr2491820c0g008",
	//   "1a": "8jze4merv08q6med3u21y460fjdcphkyuc858538mh48zu8az39t1vxdg9tadzun",
	// })
	// assert.NoError(err)
	// assert.Equal("nofu4jdoabl26vkk4yort5iaxni2bs5wa7uk75q5t75caqfptrpa", h)
}
