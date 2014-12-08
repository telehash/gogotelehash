package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"text/tabwriter"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/docopt/docopt-go"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/util/tracer"
)

var usage = `Test tool for telehash

Usage:
  th-test list
  th-test <test> <role>
  th-test -h | --help
  th-test --version

Options:
  -h --help  Show this screen.
  --version  Show version.
`

func main() {
	args, _ := docopt.Parse(usage, nil, true, "0.1", false)

	var (
		isListCmd, _ = args["list"].(bool)
		testName, _  = args["<test>"].(string)
		roleName, _  = args["<role>"].(string)
	)

	switch {
	case isListCmd:
		runList()
	default:
		runTest(testName, roleName)
	}
}

type Test struct {
	Name   string
	worker func(*Context) error
	driver func(*Context) error
}

var tests = map[string]*Test{}

func runList() {
	tab := tabwriter.NewWriter(os.Stdout, 8, 8, 2, ' ', 0)

	var sorted SortedTests
	for _, t := range tests {
		sorted = append(sorted, t)
	}
	sort.Sort(sorted)

	for _, t := range sorted {
		worker, driver := "-", "-"
		if t.worker != nil {
			worker = "worker"
		}
		if t.driver != nil {
			driver = "driver"
		}
		fmt.Fprintf(tab, "%s\t%s\t%s\n", t.Name, worker, driver)
	}

	tab.Flush()
}

func runTest(test, role string) {
	var (
		t   = tests[test]
		f   func(*Context) error
		ctx = &Context{role: role, Out: os.Stderr}
	)

	if t == nil {
		fmt.Printf("unknown test %q\n", test)
		os.Exit(1)
	}

	switch role {
	case "worker":
		f = t.worker
	case "driver":
		f = t.driver
	default:
		f = nil
	}

	if f == nil {
		fmt.Printf("unable to assume role %q for test %q\n", role, test)
		os.Exit(1)
	}

	err := f(ctx)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}

type SortedTests []*Test

func (s SortedTests) Len() int           { return len(s) }
func (s SortedTests) Less(i, j int) bool { return s[i].Name < s[j].Name }
func (s SortedTests) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func RegisterTest(name string) *Test {
	if tests[name] != nil {
		panic("must be unique")
	}

	t := &Test{Name: name}
	tests[name] = t
	return t
}

func (t *Test) Worker(f func(*Context) error) *Test {
	t.worker = f
	return t
}

func (t *Test) Driver(f func(*Context) error) *Test {
	t.driver = f
	return t
}

type Context struct {
	dir  string
	role string
	Out  io.Writer
}

func (c *Context) WriteIdentity(e *e3x.Endpoint) {
	if c.dir == "" {
		if _, err := os.Stat("/shared"); err == nil {
			c.dir = "/shared"
		} else {
			c.dir = os.TempDir()
		}
	}

	ident, err := e.LocalIdentity()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	data, err := json.Marshal(ident)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	err = ioutil.WriteFile(path.Join(c.dir, "id_"+c.role+".json"), data, 0644)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}

func (c *Context) ReadIdentity(role string) *e3x.Identity {

	if c.dir == "" {
		if _, err := os.Stat("/shared"); err == nil {
			c.dir = "/shared"
		} else {
			c.dir = os.TempDir()
		}
	}

	data, err := ioutil.ReadFile(path.Join(c.dir, "id_"+role+".json"))
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	var ident *e3x.Identity
	err = json.Unmarshal(data, &ident)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}

	return ident
}

func (c *Context) Ready() {
	tracer.Emit("ready", tracer.Info{})
}

func (c *Context) Done() {
	tracer.Emit("done", tracer.Info{})
}

func (c *Context) Assert(id int, value string) {
	tracer.Emit("assert", tracer.Info{
		"assrt_id": id,
		"value":    value,
	})
}
