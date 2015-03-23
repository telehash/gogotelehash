package base32util

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"testing/quick"
)

func TestAddRemovePadding(t *testing.T) {
	var tab = [][2]string{
		{"", ""},
		{"66", "my"},
		{"666f", "mzxq"},
		{"666f6f", "mzxw6"},
		{"666f6f62", "mzxw6yq"},
		{"666f6f6261", "mzxw6ytb"},
		{"666f6f626172", "mzxw6ytboi"},
		{"666f6f62617262", "mzxw6ytbojra"},
		{"666f6f6261726261", "mzxw6ytbojrgc"},
		{"666f6f626172626178", "mzxw6ytbojrgc6a"},
		{"9f", "t4"},
		{"9fa9", "t6uq"},
		{"9fa9e0", "t6u6a"},
		{"9fa9e037", "t6u6any"},
		{"9fa9e03792", "t6u6an4s"},
		{"9fa9e0379247", "t6u6an4si4"},
		{"9fa9e0379247ca", "t6u6an4si7fa"},
		{"9fa9e0379247cad2", "t6u6an4si7fne"},
		{"9fa9e0379247cad2d3", "t6u6an4si7fnfuy"},
		{"9fa9e0379247cad2d395", "t6u6an4si7fnfu4v"},
		{"9fa9e0379247cad2d395ad", "t6u6an4si7fnfu4vvu"},
		{"9fa9e0379247cad2d395ad7e", "t6u6an4si7fnfu4vvv7a"},
		{"9fa9e0379247cad2d395ad7e61", "t6u6an4si7fnfu4vvv7gc"},
		{"9fa9e0379247cad2d395ad7e61c2", "t6u6an4si7fnfu4vvv7gdqq"},
		{"9fa9e0379247cad2d395ad7e61c215", "t6u6an4si7fnfu4vvv7gdqqv"},
		{"9fa9e0379247cad2d395ad7e61c215ad", "t6u6an4si7fnfu4vvv7gdqqvvu"},
		{"9fa9e0379247cad2d395ad7e61c215ad32", "t6u6an4si7fnfu4vvv7gdqqvvuza"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f7", "t6u6an4si7fnfu4vvv7gdqqvvuzpo"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2a"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f76838", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2by"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382c", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byfq"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd4", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftka"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44c", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkey"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf0", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4a"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l4"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5a", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5na"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5ae7", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5noo"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5ae780", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5nopaa"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5ae78088", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5nopaei"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5ae780884a", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5nopaeiji"},
		{"9fa9e0379247cad2d395ad7e61c215ad32f768382cd44cf03f5f5ae780884a98", "t6u6an4si7fnfu4vvv7gdqqvvuzpo2byftkez4b7l5nopaeijkma"},
	}
	for i, r := range tab {
		s, _ := hex.DecodeString(r[0])
		x := EncodeToString(s)
		if x != r[1] {
			t.Errorf("#%d failed expected %q instead of %q for EncodeToString", i, r[1], x)
		}

		y, _ := DecodeString(x)
		if !bytes.Equal(y, s) {
			t.Errorf("#%d failed expected %q instead of %q for DecodeString", i, r[1], string(y))
		}
	}

	f := func(x0 []byte) bool {
		y0 := EncodeToString(x0)

		if strings.ContainsRune(y0, '=') {
			return false
		}

		x1, err := DecodeString(y0)
		if err != nil || !bytes.Equal(x0, x1) {
			return false
		}

		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
