package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/docopt/docopt-go"

	_ "github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/hashname"
)

const usage = `Telehash key generation tool.

Usage:
  th-keygen [--output=<file>]
  th-keygen -h | --help
  th-keygen --version

Options:
  -o --output=<file>  Location to store the keys. [default: -]
  -h --help           Show this screen.
  --version           Show version.
`

func main() {
	args, _ := docopt.Parse(usage, nil, true, "0.1-dev", false)

	var (
		output = args["--output"].(string)
		keys   cipherset.PrivateKeys
		data   []byte
		err    error
		out    struct {
			Hashname hashname.H            `json:"hashname,omitempty"`
			Parts    cipherset.Parts       `json:"parts,omitempty"`
			Keys     cipherset.PrivateKeys `json:"keys,omitempty"`
		}
	)

	keys, err = cipherset.GenerateKeys()
	assert(err)

	out.Keys = keys
	out.Parts = keys.ToPublicKeys().ToParts()
	out.Hashname = out.Parts.ToHashname()

	if len(out.Keys) == 0 {
		out.Keys = nil
	}
	if len(out.Parts) == 0 {
		out.Keys = nil
	}

	data, err = json.MarshalIndent(out, "", "  ")
	assert(err)

	fmt.Fprintf(os.Stderr, "Generated keys for: %s\n", out.Hashname)

	if output == "-" {
		fmt.Println(string(data))
	} else {
		err := ioutil.WriteFile(output, data, 0600)
		assert(err)
	}
}

func assert(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
