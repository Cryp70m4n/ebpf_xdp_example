package main

import (
	"fmt"
	"net"
	"log"
	"time"
    "os"
    "os/signal"
    "syscall"
	"bytes"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

)


const (
	interfaceName = "enp4s0"
	bpfObjectName = "omega.bpf.o"
	mapName = "rb"
	functionName = "receive_egress"
)


type PacketEvt struct {
	SrcIP   uint32
	DestIP   uint32
	SrcPort uint16
	DestPort uint16
}

type Event struct {
	Source string
	Destination string
	Timestamp string
}


func formatIpPort(ip uint32, port uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24), port)
}


func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	obj, err := ebpf.LoadCollection(bpfObjectName)
	if err != nil {
		panic(fmt.Sprintf("Failed to load eBPF object: %v", err))
	}
	defer obj.Close()

	prog, found := obj.Programs[functionName]
	if !found {
		panic("Failed to find eBPF program")
	}

    
    iface_idx, err := net.InterfaceByName(interfaceName)
    if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", interfaceName, err));
    }

    opts := link.XDPOptions{
		Program:   prog,
        Interface: iface_idx.Index,
    }

    lnk, err := link.AttachXDP(opts)
    if err != nil {
		panic(err)
    }
    defer lnk.Close()

    fmt.Println("Successfully loaded and attached BPF program.");

	ringBuf, found := obj.Maps[mapName]
	if !found {
		panic(fmt.Sprintf("Failed to find ring buffer map named '%s'", mapName))
	}

	rbReader, err := ringbuf.NewReader(ringBuf)
	if err != nil {
		panic(fmt.Sprintf("Failed to create ring buffer reader: %v", err))
	}
	defer rbReader.Close()


	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nExiting...")
		rbReader.Close()
		lnk.Close()
		os.Exit(0)
	}()


	for {
		record, err := rbReader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}
			//log.Printf("Error reading ring buffer: %v", err)
			continue
		}

		var evt PacketEvt
		reader := bytes.NewReader(record.RawSample)
		err = binary.Read(reader, binary.LittleEndian, &evt)
    	if err != nil {
        	log.Printf("Failed to decode event: %v", err)
        	continue
    	}
		//events := make(map[string]string)
		//events[formatIpPort(evt.SrcIP, evt.SrcPort)] = formatIpPort(evt.DestIP, evt.DestPort)
		//fmt.Printf("Received Event => (SRC) -> [%s] | (DEST) -> [%s]\n",
		//	formatIpPort(evt.SrcIP, evt.SrcPort), events[formatIpPort(evt.SrcIP, evt.SrcPort)])

		var events []Event
		var counter int
		counter = 0
		currentTime := time.Now()
		formattedTime := currentTime.Format("2006-01-02 15:04:05")
		events = append(events, Event{Source: formatIpPort(evt.SrcIP, evt.SrcPort), Destination: formatIpPort(evt.DestIP, evt.DestPort), Timestamp: formattedTime});
		fmt.Println(events[counter]);
		counter++;
	}
}
