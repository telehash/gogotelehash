package hashname

import (
	"testing"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/stretchr/testify/assert"
)

func TestCoding(t *testing.T) {
	var (
		assert = assert.New(t)
	)

	assert.True(!H("").Valid(),
		`expected H("") to be invalid`)

	assert.True(!H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3m").Valid(),
		`expected H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3m") to be invalid`)

	assert.True(!H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa33").Valid(),
		`expected H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa33") to be invalid`)

	assert.True(H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa").Valid(),
		`expected H("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa") to be valid`)
}
