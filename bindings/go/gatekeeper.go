package gatekeeper

//go:generate ./build_go.sh

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo linux LDFLAGS: ${SRCDIR}/lib/linux/libgatekeeper.a -lm -ldl -lpthread
#cgo darwin LDFLAGS: ${SRCDIR}/lib/darwin/libgatekeeper.a -lm -framework Security -framework CoreFoundation
#cgo windows LDFLAGS: ${SRCDIR}/lib/windows/gatekeeper.lib -lws2_32 -luserenv -lbcrypt
#include "gatekeeper.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// SniffFormat inspects the raw file bytes to determine its format without fully decoding it.
func SniffFormat(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("payload is empty")
	}

	cRaw := (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	cLen := C.size_t(len(payload))

	// Allocate a small buffer for the format string (e.g. "Jpeg", "Png")
	outLen := C.size_t(16)
	cOutFmt := (*C.uint8_t)(C.malloc(outLen))
	if cOutFmt == nil {
		return "", errors.New("failed to allocate memory")
	}
	defer C.free(unsafe.Pointer(cOutFmt))

	result := C.gatekeeper_sniff_format(cRaw, cLen, cOutFmt, outLen)
	if result != 0 {
		return "", fmt.Errorf("unrecognised file magic or format error (code: %d)", result)
	}

	// Convert the C string back to Go
	goStr := C.GoString((*C.char)(unsafe.Pointer(cOutFmt)))
	return goStr, nil
}

type DisarmResult struct {
	Buffer       []byte
	PngBuffer    []byte // nil if no png output
	OutputFormat string
}

// Disarm sanitizes the input payload by stripping all metadata and potential exploits,
// reconstructing a safe file from the raw pixel data.
func Disarm(payload []byte) (*DisarmResult, error) {
	if len(payload) == 0 {
		return nil, errors.New("payload is empty")
	}

	cRaw := (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	cLen := C.size_t(len(payload))

	// Call the native Rust CDR engine
	result := C.gatekeeper_disarm(cRaw, cLen)
	
	// Ensure we free the Rust heap memory
	defer C.gatekeeper_free_result(result)

	if !result.ok {
		return nil, fmt.Errorf("Gatekeeper CDR failed (error code: %d)", result.error_code)
	}

	// Copy the data from the Rust-managed C pointer into a new Go byte slice.
	cleanSlice := C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))
	
	var pngSlice []byte
	if result.png_len > 0 && result.png_data != nil {
		pngSlice = C.GoBytes(unsafe.Pointer(result.png_data), C.int(result.png_len))
	}

	outFmt := C.GoString((*C.char)(unsafe.Pointer(&result.output_format[0])))

	return &DisarmResult{
		Buffer:       cleanSlice,
		PngBuffer:    pngSlice,
		OutputFormat: outFmt,
	}, nil
}
