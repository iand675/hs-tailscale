// Package main provides C-compatible FFI bindings for tsnet.
//
// Build with: go build -buildmode=c-shared -o libtsnet.so tsnet_ffi.go
//
// This creates a shared library that can be called from Haskell via FFI.
package main

/*
#include <stdlib.h>
#include <stdint.h>

// Server handle
typedef struct {
    void* ptr;
} TSNetServer;

// Listener handle
typedef struct {
    void* ptr;
} TSNetListener;

// Connection handle
typedef struct {
    void* ptr;
} TSNetConn;

// Result structure for operations that can fail
typedef struct {
    int success;
    char* error;
} TSNetResult;

// IP address pair
typedef struct {
    char* ipv4;
    char* ipv6;
} TSNetIPs;

// Listener address info
typedef struct {
    char* network;
    char* addr;
} TSNetListenerAddr;
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"unsafe"

	"tailscale.com/tsnet"
)

var (
	// Global registry for managing handles
	mu        sync.RWMutex
	servers   = make(map[uint64]*tsnet.Server)
	listeners = make(map[uint64]net.Listener)
	conns     = make(map[uint64]net.Conn)
	nextID    uint64 = 1
)

func getNextID() uint64 {
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	return id
}

//export tsnet_server_new
func tsnet_server_new(hostname *C.char, authKey *C.char, ephemeral C.int, stateDir *C.char) C.uint64_t {
	s := &tsnet.Server{}

	if hostname != nil {
		s.Hostname = C.GoString(hostname)
	}
	if authKey != nil {
		s.AuthKey = C.GoString(authKey)
	}
	if ephemeral != 0 {
		s.Ephemeral = true
	}
	if stateDir != nil {
		s.Dir = C.GoString(stateDir)
	}

	id := getNextID()
	mu.Lock()
	servers[id] = s
	mu.Unlock()

	return C.uint64_t(id)
}

//export tsnet_server_start
func tsnet_server_start(serverID C.uint64_t) C.TSNetResult {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	err := s.Start()
	if err != nil {
		return C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_up
func tsnet_server_up(serverID C.uint64_t) C.TSNetResult {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	ctx := context.Background()
	_, err := s.Up(ctx)
	if err != nil {
		return C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_close
func tsnet_server_close(serverID C.uint64_t) C.TSNetResult {
	mu.Lock()
	s, ok := servers[uint64(serverID)]
	if ok {
		delete(servers, uint64(serverID))
	}
	mu.Unlock()

	if !ok {
		return C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	err := s.Close()
	if err != nil {
		return C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_tailscale_ips
func tsnet_server_tailscale_ips(serverID C.uint64_t) C.TSNetIPs {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return C.TSNetIPs{ipv4: nil, ipv6: nil}
	}

	ip4, ip6 := s.TailscaleIPs()

	var result C.TSNetIPs
	if ip4.IsValid() {
		result.ipv4 = C.CString(ip4.String())
	}
	if ip6.IsValid() {
		result.ipv6 = C.CString(ip6.String())
	}

	return result
}

//export tsnet_server_cert_domains
func tsnet_server_cert_domains(serverID C.uint64_t, outLen *C.int) **C.char {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		*outLen = 0
		return nil
	}

	domains := s.CertDomains()
	*outLen = C.int(len(domains))

	if len(domains) == 0 {
		return nil
	}

	// Allocate array of C strings
	cArray := C.malloc(C.size_t(len(domains)) * C.size_t(unsafe.Sizeof((*C.char)(nil))))
	goSlice := unsafe.Slice((**C.char)(cArray), len(domains))

	for i, d := range domains {
		goSlice[i] = C.CString(d)
	}

	return (**C.char)(cArray)
}

//export tsnet_server_listen
func tsnet_server_listen(serverID C.uint64_t, network *C.char, addr *C.char) (C.uint64_t, C.TSNetResult) {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	ln, err := s.Listen(C.GoString(network), C.GoString(addr))
	if err != nil {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	id := getNextID()
	mu.Lock()
	listeners[id] = ln
	mu.Unlock()

	return C.uint64_t(id), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_listen_tls
func tsnet_server_listen_tls(serverID C.uint64_t, network *C.char, addr *C.char) (C.uint64_t, C.TSNetResult) {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	ln, err := s.ListenTLS(C.GoString(network), C.GoString(addr))
	if err != nil {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	id := getNextID()
	mu.Lock()
	listeners[id] = ln
	mu.Unlock()

	return C.uint64_t(id), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_listen_funnel
func tsnet_server_listen_funnel(serverID C.uint64_t, network *C.char, addr *C.char, funnelOnly C.int) (C.uint64_t, C.TSNetResult) {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	var opts []tsnet.FunnelOption
	if funnelOnly != 0 {
		opts = append(opts, tsnet.FunnelOnly())
	}

	ln, err := s.ListenFunnel(C.GoString(network), C.GoString(addr), opts...)
	if err != nil {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	id := getNextID()
	mu.Lock()
	listeners[id] = ln
	mu.Unlock()

	return C.uint64_t(id), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_server_dial
func tsnet_server_dial(serverID C.uint64_t, network *C.char, address *C.char) (C.uint64_t, C.TSNetResult) {
	mu.RLock()
	s, ok := servers[uint64(serverID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("server not found"),
		}
	}

	ctx := context.Background()
	conn, err := s.Dial(ctx, C.GoString(network), C.GoString(address))
	if err != nil {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	id := getNextID()
	mu.Lock()
	conns[id] = conn
	mu.Unlock()

	return C.uint64_t(id), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_listener_accept
func tsnet_listener_accept(listenerID C.uint64_t) (C.uint64_t, C.TSNetResult) {
	mu.RLock()
	ln, ok := listeners[uint64(listenerID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("listener not found"),
		}
	}

	conn, err := ln.Accept()
	if err != nil {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	id := getNextID()
	mu.Lock()
	conns[id] = conn
	mu.Unlock()

	return C.uint64_t(id), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_listener_addr
func tsnet_listener_addr(listenerID C.uint64_t) C.TSNetListenerAddr {
	mu.RLock()
	ln, ok := listeners[uint64(listenerID)]
	mu.RUnlock()

	if !ok {
		return C.TSNetListenerAddr{network: nil, addr: nil}
	}

	addr := ln.Addr()
	return C.TSNetListenerAddr{
		network: C.CString(addr.Network()),
		addr:    C.CString(addr.String()),
	}
}

//export tsnet_listener_close
func tsnet_listener_close(listenerID C.uint64_t) C.TSNetResult {
	mu.Lock()
	ln, ok := listeners[uint64(listenerID)]
	if ok {
		delete(listeners, uint64(listenerID))
	}
	mu.Unlock()

	if !ok {
		return C.TSNetResult{
			success: 0,
			error:   C.CString("listener not found"),
		}
	}

	err := ln.Close()
	if err != nil {
		return C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.TSNetResult{success: 1, error: nil}
}

//export tsnet_conn_read
func tsnet_conn_read(connID C.uint64_t, buf *C.char, bufLen C.int) (C.int, C.TSNetResult) {
	mu.RLock()
	conn, ok := conns[uint64(connID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("connection not found"),
		}
	}

	goBuf := make([]byte, int(bufLen))
	n, err := conn.Read(goBuf)

	if n > 0 {
		C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&goBuf[0]), C.size_t(n))
	}

	if err != nil && err != io.EOF {
		return C.int(n), C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	if err == io.EOF {
		return C.int(n), C.TSNetResult{
			success: 2, // Special code for EOF
			error:   nil,
		}
	}

	return C.int(n), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_conn_write
func tsnet_conn_write(connID C.uint64_t, buf *C.char, bufLen C.int) (C.int, C.TSNetResult) {
	mu.RLock()
	conn, ok := conns[uint64(connID)]
	mu.RUnlock()

	if !ok {
		return 0, C.TSNetResult{
			success: 0,
			error:   C.CString("connection not found"),
		}
	}

	goBuf := C.GoBytes(unsafe.Pointer(buf), bufLen)
	n, err := conn.Write(goBuf)

	if err != nil {
		return C.int(n), C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.int(n), C.TSNetResult{success: 1, error: nil}
}

//export tsnet_conn_remote_addr
func tsnet_conn_remote_addr(connID C.uint64_t) *C.char {
	mu.RLock()
	conn, ok := conns[uint64(connID)]
	mu.RUnlock()

	if !ok {
		return nil
	}

	return C.CString(conn.RemoteAddr().String())
}

//export tsnet_conn_local_addr
func tsnet_conn_local_addr(connID C.uint64_t) *C.char {
	mu.RLock()
	conn, ok := conns[uint64(connID)]
	mu.RUnlock()

	if !ok {
		return nil
	}

	return C.CString(conn.LocalAddr().String())
}

//export tsnet_conn_close
func tsnet_conn_close(connID C.uint64_t) C.TSNetResult {
	mu.Lock()
	conn, ok := conns[uint64(connID)]
	if ok {
		delete(conns, uint64(connID))
	}
	mu.Unlock()

	if !ok {
		return C.TSNetResult{
			success: 0,
			error:   C.CString("connection not found"),
		}
	}

	err := conn.Close()
	if err != nil {
		return C.TSNetResult{
			success: 0,
			error:   C.CString(err.Error()),
		}
	}

	return C.TSNetResult{success: 1, error: nil}
}

//export tsnet_free_string
func tsnet_free_string(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

//export tsnet_free_string_array
func tsnet_free_string_array(arr **C.char, len C.int) {
	if arr == nil {
		return
	}
	goSlice := unsafe.Slice(arr, int(len))
	for _, s := range goSlice {
		C.free(unsafe.Pointer(s))
	}
	C.free(unsafe.Pointer(arr))
}

func main() {}
