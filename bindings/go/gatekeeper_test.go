package gatekeeper

import (
	"strings"
	"testing"
)

func TestSniffFormat_Unknown(t *testing.T) {
	_, err := SniffFormat([]byte("this_is_a_random_string_that_is_not_an_image"))
	if err == nil {
		t.Fatal("Expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognised file magic") {
		t.Fatalf("Expected unrecognised file magic error, got: %v", err)
	}
}

func TestSniffFormat_Empty(t *testing.T) {
	_, err := SniffFormat([]byte{})
	if err == nil {
		t.Fatal("Expected error for empty payload")
	}
}

func TestSniffFormat_PNG(t *testing.T) {
	// Structural PNG header
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	chunkLen := []byte{0x00, 0x00, 0x00, 0x0D}
	chunkType := []byte("IHDR")
	
	validPngHeader := append(pngSig, chunkLen...)
	validPngHeader = append(validPngHeader, chunkType...)

	fmt, err := SniffFormat(validPngHeader)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if fmt != "Png" {
		t.Fatalf("Expected 'Png', got '%s'", fmt)
	}
}

func TestSniffFormat_JPEG(t *testing.T) {
	soi := []byte{0xFF, 0xD8}
	app0 := []byte{0xFF, 0xE0, 0x00, 0x10}
	jfif := append([]byte("JFIF\x00"), 0x01, 0x01, 0x00)
	eoi := []byte{0xFF, 0xD9}

	validJpegHeader := append(soi, app0...)
	validJpegHeader = append(validJpegHeader, jfif...)
	validJpegHeader = append(validJpegHeader, eoi...)

	fmt, err := SniffFormat(validJpegHeader)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if fmt != "Jpeg" {
		t.Fatalf("Expected 'Jpeg', got '%s'", fmt)
	}
}

func TestDisarm_Invalid(t *testing.T) {
	_, err := Disarm([]byte("invalid_payload"))
	if err == nil {
		t.Fatal("Expected error for invalid disarm payload, got nil")
	}
}

func TestDisarm_Empty(t *testing.T) {
	_, err := Disarm([]byte{})
	if err == nil {
		t.Fatal("Expected error for empty payload")
	}
}
