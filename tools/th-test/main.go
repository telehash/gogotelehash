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
	sut    func(*Context) error
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
		sut, drv := "-", "-"
		if t.sut != nil {
			sut = "sut"
		}
		if t.driver != nil {
			drv = "drv"
		}
		fmt.Fprintf(tab, "%s\t%s\t%s\n", t.Name, sut, drv)
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
	case "sut":
		f = t.sut
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

func (t *Test) SUT(f func(*Context) error) *Test {
	t.sut = f
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

func (c *Context) WriteIdenity(e *e3x.Endpoint) {
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

func (c *Context) ReadIdenity(role string) *e3x.Identity {

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
	fmt.Fprintln(os.Stdout, `{"cmd":"ready"}`)
}

func (c *Context) Done() {
	fmt.Fprintln(os.Stdout, `{"cmd":"done"}`)
}

type Command struct {
	Cmd      string `json:"cmd"`
	Process  string `json:"proc,omitempty"`
	Line     string `json:"line,omitempty"`
	ExitCode int    `json:"code,omitempty"`
	ID       int    `json:"id,omitempty"`
	Value    string `json:"value,omitempty"`
}

func (c *Context) WriteCommand(cmd *Command) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	_, err = fmt.Println(string(data))
	return err
}

func (c *Context) Assert(id int, value string) {
	err := c.WriteCommand(&Command{Cmd: "assert", ID: id, Value: value})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
