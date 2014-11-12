package main

import (
	"log"
	"sync"

	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/huin/goupnp"
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/telehash/gogotelehash/Godeps/_workspace/src/github.com/huin/goupnp/dcps/internetgateway2"
)

func main() {
	for _, dev := range findDevices() {
		log.Printf("dev: %s", dev.Device.String())

		dev.Device.VisitServices(func(srv *goupnp.Service) {
			log.Printf("- %s", srv.String())
		})
	}
}

func findDevices() map[string]*goupnp.RootDevice {
	var (
		wg   = &sync.WaitGroup{}
		map1 = map[string]*goupnp.RootDevice{}
		map2 = map[string]*goupnp.RootDevice{}
		map3 = map[string]*goupnp.RootDevice{}
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		devs, err := goupnp.DiscoverDevices(internetgateway1.URN_WANConnectionDevice_1)
		if err != nil {
			return
		}

		for _, dev := range devs {
			if dev.Root != nil {
				map1[dev.Root.Device.SerialNumber] = dev.Root
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		devs, err := goupnp.DiscoverDevices(internetgateway2.URN_WANConnectionDevice_1)
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		for _, dev := range devs {
			if dev.Root != nil {
				map2[dev.Root.Device.SerialNumber] = dev.Root
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		devs, err := goupnp.DiscoverDevices(internetgateway2.URN_WANConnectionDevice_2)
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		for _, dev := range devs {
			if dev.Root != nil {
				map3[dev.Root.Device.SerialNumber] = dev.Root
			}
		}
	}()

	wg.Wait()

	for id, dev := range map2 {
		if _, f := map1[id]; !f {
			map1[id] = dev
		}
	}

	for id, dev := range map3 {
		if _, f := map1[id]; !f {
			map1[id] = dev
		}
	}

	return map1
}
