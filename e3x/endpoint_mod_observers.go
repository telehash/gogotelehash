package e3x

import (
	"reflect"
)

// Observers is an internal module which allows other modules to observe
// endpoint changes.
type Observers interface {

	// Register a observer function. f must have a signature of func(*T)
	// Where T is a observable event.
	Register(f interface{})

	// Trigger an event.
	// Only use this module when you know what you are doeing.
	Trigger(event interface{})
}

// ObserversFromEndpoint returns the Observers module for Endpoint.
func ObserversFromEndpoint(e *Endpoint) Observers {
	mod := e.Module(modObserversKey)
	if mod == nil {
		return nil
	}
	return mod.(*modObservers)
}

const modObserversKey = modObserversKeyType("observers")

type modObserversKeyType string

type modObservers struct {
	observers map[reflect.Type][]reflect.Value
}

func (mod *modObservers) Init() error  { return nil }
func (mod *modObservers) Start() error { return nil }
func (mod *modObservers) Stop() error  { return nil }

func (mod *modObservers) Register(f interface{}) {
	var (
		v         = reflect.ValueOf(f)
		t         = v.Type()
		eventType reflect.Type
	)

	if v.Kind() != reflect.Func {
		panic("Observers: f must be a function")
	}

	if t.IsVariadic() || t.NumIn() != 1 || t.NumOut() != 0 {
		panic("Observers: f must have the signature func(*T) where T is a struct type")
	}

	if t.In(0).Kind() != reflect.Ptr {
		panic("Observers: f must have the signature func(*T) where T is a struct type")
	}

	eventType = t.In(0).Elem()
	if eventType.Kind() != reflect.Struct {
		panic("Observers: f must have the signature func(*T) where T is a struct type")
	}

	if mod.observers == nil {
		mod.observers = make(map[reflect.Type][]reflect.Value)
	}

	mod.observers[eventType] = append(
		mod.observers[eventType],
		v,
	)
}

func (mod *modObservers) Trigger(event interface{}) {
	if event == nil {
		return
	}

	var (
		v = reflect.ValueOf(event)
		t = v.Type()
	)

	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct {
		panic("Observers: event must be *T where T is a struct type")
	}

	if mod.observers == nil {
		return
	}

	for _, fv := range mod.observers[t.Elem()] {
		go fv.Call([]reflect.Value{v})
	}
}
