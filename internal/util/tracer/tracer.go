package tracer

import (
	"encoding/json"
	"log"
	"os"
	"sync/atomic"
)

type ID uint64
type Info map[string]interface{}

var (
	Enabled      bool   = os.Getenv("TH_TRACER") == "on"
	lastTracerId uint64 = 0
	logger       *log.Logger
)

func init() {
	logger = log.New(os.Stdout, "", 0)
}

func NewID() ID {
	return ID(atomic.AddUint64(&lastTracerId, 1))
}

func Emit(typ string, info interface{}) {
	if !Enabled {
		return
	}

	if typ == "" {
		panic("type must not be blank")
	}

	e := event{
		Type: typ,
		ID:   NewID(),
		Info: info,
	}

	data, err := json.Marshal(&e)
	if err != nil {
		panic(err)
	}

	logger.Println(string(data))
}

type event struct {
	ID   ID          `json:"id"`
	Type string      `json:"ty"`
	Info interface{} `json:"in,omitempty"`
}
