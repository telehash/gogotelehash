package kademlia

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/util/base32util"
)

func Test_addCandidate(t *testing.T) {
	var tab table
	tab.localHashname = hashname.H("e5arfhyzpisdaxf7bfnyeqn5fuyjalrcali3fcxgqybxlms2emna")
	tab.init()

	tab.addCandidate(
		hashname.H("ws3nbxcqxcoaebzcixpw2k676id63zq3gouvufybwrq6bnlglisq"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	tab.addCandidate(
		hashname.H("jrrkl7ey4u5nbhsga7afjx72lzoy6bwtm5obikwqtvpnb5lszr6q"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	tab.addCandidate(
		hashname.H("wkwllldvgxwew7foyfp4jvjdi2k62jh6anugplksvg4sxybcjyfq"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	tab.addCandidate(
		hashname.H("qwaluf7cgrfevyauorr2xljsnv7il5tkivuniqzx2l56d7r45dbq"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	tab.addCandidate(
		hashname.H("e5arfhyzpisdaxf7bfnyeqn5fuyjalrcali3fcxgqybxlms2emn7"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	tab.addCandidate(
		hashname.H("e5arfhyzpisdaxf7bfnyeqn5fuyjalrcali3fcxgqybxlms2emoa"),
		hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza"))

	router := hashname.H("xfmdgpp6akgv5knoptrn6h3wep2aaxrpaqbd6wxhp2rpwqh5vrza")
	for i := 0; i < 10000; i++ {
		tab.addCandidate(makeRandomHashname(), router)
	}

	t.Logf("tab=%v", &tab)
}

func makeRandomHashname() hashname.H {
	var buf [32]byte

	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}

	return hashname.H(base32util.EncodeToString(buf[:]))
}
