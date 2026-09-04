// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// mockURLFetcher is a mock implementation of URLFetcher for testing.
type mockURLFetcher struct {
	data        map[string][]byte // URL -> data
	fetchErr    error             // error to return on fetch
	fetchedURLs []string          // track which URLs were fetched
}

func (m *mockURLFetcher) Fetch(url string, tlsCA []byte) ([]byte, error) {
	m.fetchedURLs = append(m.fetchedURLs, url)
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	if data, ok := m.data[url]; ok {
		return data, nil
	}
	return nil, errors.New("URL not found")
}

// mockMetaPayloadVerifier is a mock implementation of MetaPayloadVerifier for testing.
type mockMetaPayloadVerifier struct {
	verifyErr error
	payload   []byte // payload to return after verification
}

func (m *mockMetaPayloadVerifier) Verify(signedPayload []byte, signerKey []byte) ([]byte, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	if m.payload != nil {
		return m.payload, nil
	}
	// Return the payload as-is (simulating unsigned)
	return signedPayload, nil
}

// mockUnifiedImageHandler is a mock implementation of UnifiedImageHandler for testing.
type mockUnifiedImageHandler struct {
	receivedImages []receivedImage
	returnStatus   int
	returnMessage  string
	returnErr      error
}

type receivedImage struct {
	imageType string
	name      string
	size      uint64
	metadata  map[string]any
	data      []byte
}

func (m *mockUnifiedImageHandler) HandleImage(ctx context.Context, imageType, name string, size uint64, metadata map[string]any, image []byte) (statusCode int, message string, err error) {
	m.receivedImages = append(m.receivedImages, receivedImage{
		imageType: imageType,
		name:      name,
		size:      size,
		metadata:  metadata,
		data:      image,
	})
	return m.returnStatus, m.returnMessage, m.returnErr
}

func TestMetaPayloadMarshalUnmarshal(t *testing.T) {
	original := MetaPayload{
		MIMEType:     "application/x-iso9660-image",
		URL:          "https://example.com/image.iso",
		TLSCA:        []byte{0x01, 0x02, 0x03},
		HashAlg:      "sha256",
		ExpectedHash: []byte{0x04, 0x05, 0x06},
		BootArgs:     "console=ttyS0",
		Name:         "test-image",
		Version:      "1.0.0",
		Description:  "Test image description",
	}

	// Marshal
	data, err := original.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	// Unmarshal
	var decoded MetaPayload
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	// Verify
	if decoded.MIMEType != original.MIMEType {
		t.Errorf("MIMEType mismatch: got %q, want %q", decoded.MIMEType, original.MIMEType)
	}
	if decoded.URL != original.URL {
		t.Errorf("URL mismatch: got %q, want %q", decoded.URL, original.URL)
	}
	if !bytes.Equal(decoded.TLSCA, original.TLSCA) {
		t.Errorf("TLSCA mismatch: got %v, want %v", decoded.TLSCA, original.TLSCA)
	}
	if decoded.HashAlg != original.HashAlg {
		t.Errorf("HashAlg mismatch: got %q, want %q", decoded.HashAlg, original.HashAlg)
	}
	if !bytes.Equal(decoded.ExpectedHash, original.ExpectedHash) {
		t.Errorf("ExpectedHash mismatch: got %v, want %v", decoded.ExpectedHash, original.ExpectedHash)
	}
	if decoded.BootArgs != original.BootArgs {
		t.Errorf("BootArgs mismatch: got %q, want %q", decoded.BootArgs, original.BootArgs)
	}
	if decoded.Name != original.Name {
		t.Errorf("Name mismatch: got %q, want %q", decoded.Name, original.Name)
	}
	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: got %q, want %q", decoded.Version, original.Version)
	}
	if decoded.Description != original.Description {
		t.Errorf("Description mismatch: got %q, want %q", decoded.Description, original.Description)
	}
}

func TestBMOOwnerAddImageURL(t *testing.T) {
	owner := &BMOOwner{}

	expectedHash := []byte{0x01, 0x02, 0x03, 0x04}
	tlsCA := []byte{0x05, 0x06, 0x07, 0x08}

	owner.AddImageURL("application/x-iso9660-image", "https://example.com/image.iso", expectedHash, tlsCA)

	if len(owner.images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(owner.images))
	}

	img := owner.images[0]
	if img.ImageType != "application/x-iso9660-image" {
		t.Errorf("ImageType mismatch: got %q", img.ImageType)
	}
	if img.DeliveryMode != DeliveryModeURL {
		t.Errorf("DeliveryMode mismatch: got %d, want %d", img.DeliveryMode, DeliveryModeURL)
	}
	if img.URL != "https://example.com/image.iso" {
		t.Errorf("URL mismatch: got %q", img.URL)
	}
	if !bytes.Equal(img.ExpectedHash, expectedHash) {
		t.Errorf("ExpectedHash mismatch")
	}
	if !bytes.Equal(img.TLSCA, tlsCA) {
		t.Errorf("TLSCA mismatch")
	}
	if !img.RequireAck {
		t.Error("RequireAck should be true for URL mode")
	}
}

func TestBMOOwnerAddImageMetaURL(t *testing.T) {
	owner := &BMOOwner{}

	metaSigner := []byte{0x01, 0x02, 0x03}
	tlsCA := []byte{0x04, 0x05, 0x06}

	owner.AddImageMetaURL("https://example.com/meta.cbor", metaSigner, tlsCA)

	if len(owner.images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(owner.images))
	}

	img := owner.images[0]
	if img.ImageType != "application/x-bmo-meta" {
		t.Errorf("ImageType mismatch: got %q", img.ImageType)
	}
	if img.DeliveryMode != DeliveryModeMetaURL {
		t.Errorf("DeliveryMode mismatch: got %d, want %d", img.DeliveryMode, DeliveryModeMetaURL)
	}
	if img.URL != "https://example.com/meta.cbor" {
		t.Errorf("URL mismatch: got %q", img.URL)
	}
	if !bytes.Equal(img.MetaSigner, metaSigner) {
		t.Errorf("MetaSigner mismatch")
	}
	if !bytes.Equal(img.TLSCA, tlsCA) {
		t.Errorf("TLSCA mismatch")
	}
	if !img.RequireAck {
		t.Error("RequireAck should be true for meta-URL mode")
	}
}

func TestBMODeviceSupportsDeliveryMode(t *testing.T) {
	tests := []struct {
		name           string
		supportedModes []uint
		mode           uint
		expected       bool
	}{
		{
			name:           "empty list supports all",
			supportedModes: nil,
			mode:           DeliveryModeURL,
			expected:       true,
		},
		{
			name:           "explicit inline only",
			supportedModes: []uint{DeliveryModeInline},
			mode:           DeliveryModeInline,
			expected:       true,
		},
		{
			name:           "explicit inline only rejects URL",
			supportedModes: []uint{DeliveryModeInline},
			mode:           DeliveryModeURL,
			expected:       false,
		},
		{
			name:           "explicit URL and meta-URL",
			supportedModes: []uint{DeliveryModeURL, DeliveryModeMetaURL},
			mode:           DeliveryModeMetaURL,
			expected:       true,
		},
		{
			name:           "explicit URL and meta-URL rejects inline",
			supportedModes: []uint{DeliveryModeURL, DeliveryModeMetaURL},
			mode:           DeliveryModeInline,
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bmo := &BMO{
				SupportedDeliveryModes: tt.supportedModes,
			}
			result := bmo.supportsDeliveryMode(tt.mode)
			if result != tt.expected {
				t.Errorf("supportsDeliveryMode(%d) = %v, want %v", tt.mode, result, tt.expected)
			}
		})
	}
}

func TestBMODeviceVerifyHash(t *testing.T) {
	bmo := &BMO{}

	// Test data
	data := []byte("test data for hashing")
	hash := sha256.Sum256(data)

	tests := []struct {
		name         string
		data         []byte
		expectedHash []byte
		hashAlg      string
		expectErr    bool
	}{
		{
			name:         "valid sha256",
			data:         data,
			expectedHash: hash[:],
			hashAlg:      "sha256",
			expectErr:    false,
		},
		{
			name:         "valid sha256 empty alg",
			data:         data,
			expectedHash: hash[:],
			hashAlg:      "",
			expectErr:    false,
		},
		{
			name:         "invalid hash",
			data:         data,
			expectedHash: []byte{0x00, 0x01, 0x02},
			hashAlg:      "sha256",
			expectErr:    true,
		},
		{
			name:         "unsupported algorithm",
			data:         data,
			expectedHash: hash[:],
			hashAlg:      "md5",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := bmo.verifyHash(tt.data, tt.expectedHash, tt.hashAlg)
			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestBMODeviceOnBeginAckDeliveryModeCheck(t *testing.T) {
	tests := []struct {
		name           string
		deliveryMode   uint
		supportedModes []uint
		hasURLFetcher  bool
		expectAccepted bool
		expectCode     int
	}{
		{
			name:           "inline mode always accepted",
			deliveryMode:   DeliveryModeInline,
			supportedModes: nil,
			hasURLFetcher:  false,
			expectAccepted: true,
		},
		{
			name:           "URL mode rejected without fetcher",
			deliveryMode:   DeliveryModeURL,
			supportedModes: nil,
			hasURLFetcher:  false,
			expectAccepted: false,
			expectCode:     BMOErrorDeliveryModeNotSupported,
		},
		{
			name:           "URL mode accepted with fetcher",
			deliveryMode:   DeliveryModeURL,
			supportedModes: nil,
			hasURLFetcher:  true,
			expectAccepted: true,
		},
		{
			name:           "URL mode rejected by supported list",
			deliveryMode:   DeliveryModeURL,
			supportedModes: []uint{DeliveryModeInline},
			hasURLFetcher:  true,
			expectAccepted: false,
			expectCode:     BMOErrorDeliveryModeNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bmo := &BMO{
				SupportedDeliveryModes: tt.supportedModes,
			}
			if tt.hasURLFetcher {
				bmo.URLFetcher = &mockURLFetcher{}
			}

			begin := chunking.BeginMessage{
				FSIMFields: map[int]any{
					-1: "application/x-iso9660-image",
					-6: uint64(tt.deliveryMode),
				},
			}

			accepted, code, _ := bmo.onBeginAck(begin)
			if accepted != tt.expectAccepted {
				t.Errorf("accepted = %v, want %v", accepted, tt.expectAccepted)
			}
			if !tt.expectAccepted && code != tt.expectCode {
				t.Errorf("code = %d, want %d", code, tt.expectCode)
			}
		})
	}
}

func TestBMODeviceURLModeEndToEnd(t *testing.T) {
	// Test data
	imageData := []byte("test image data for URL mode")
	imageHash := sha256.Sum256(imageData)
	imageURL := "https://example.com/image.bin"

	// Create mock fetcher
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			imageURL: imageData,
		},
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{
		returnStatus:  0,
		returnMessage: "success",
	}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler: handler,
		URLFetcher:     fetcher,
	}

	// Simulate receiving image-begin with URL mode
	bmo.begin = chunking.BeginMessage{
		HashAlg: "sha256",
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
			-6: uint64(DeliveryModeURL),
			-7: imageURL,
			-9: imageHash[:],
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err := endFunc(chunking.EndMessage{})

	if err != nil {
		t.Fatalf("onEndUnified failed: %v", err)
	}

	// Verify the image was fetched
	if len(fetcher.fetchedURLs) != 1 || fetcher.fetchedURLs[0] != imageURL {
		t.Errorf("expected URL %q to be fetched, got %v", imageURL, fetcher.fetchedURLs)
	}

	// Verify the handler received the image
	if len(handler.receivedImages) != 1 {
		t.Fatalf("expected 1 image, got %d", len(handler.receivedImages))
	}

	img := handler.receivedImages[0]
	if img.imageType != "application/x-iso9660-image" {
		t.Errorf("imageType mismatch: got %q", img.imageType)
	}
	if !bytes.Equal(img.data, imageData) {
		t.Errorf("image data mismatch")
	}

	// Verify result status
	if bmo.resultStatus != 0 {
		t.Errorf("resultStatus = %d, want 0", bmo.resultStatus)
	}
}

func TestBMODeviceURLModeHashMismatch(t *testing.T) {
	// Test data
	imageData := []byte("test image data")
	wrongHash := []byte{0x00, 0x01, 0x02, 0x03} // Wrong hash
	imageURL := "https://example.com/image.bin"

	// Create mock fetcher
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			imageURL: imageData,
		},
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler: handler,
		URLFetcher:     fetcher,
	}

	// Simulate receiving image-begin with URL mode and wrong hash
	bmo.begin = chunking.BeginMessage{
		HashAlg: "sha256",
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
			-6: uint64(DeliveryModeURL),
			-7: imageURL,
			-9: wrongHash,
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err := endFunc(chunking.EndMessage{})

	// Should return an error
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}

	// Verify it's a bmoURLError with correct code
	urlErr, ok := err.(*bmoURLError)
	if !ok {
		t.Fatalf("expected *bmoURLError, got %T", err)
	}
	if urlErr.code != BMOErrorHashMismatch {
		t.Errorf("error code = %d, want %d", urlErr.code, BMOErrorHashMismatch)
	}

	// Verify result status was set
	if bmo.resultStatus != 2 {
		t.Errorf("resultStatus = %d, want 2", bmo.resultStatus)
	}
}

func TestBMODeviceURLModeFetchError(t *testing.T) {
	// Create mock fetcher that returns an error
	fetcher := &mockURLFetcher{
		fetchErr: errors.New("connection refused"),
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler: handler,
		URLFetcher:     fetcher,
	}

	// Simulate receiving image-begin with URL mode
	bmo.begin = chunking.BeginMessage{
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
			-6: uint64(DeliveryModeURL),
			-7: "https://example.com/image.bin",
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err := endFunc(chunking.EndMessage{})

	// Should return an error
	if err == nil {
		t.Fatal("expected error for fetch failure, got nil")
	}

	// Verify it's a bmoURLError with correct code
	urlErr, ok := err.(*bmoURLError)
	if !ok {
		t.Fatalf("expected *bmoURLError, got %T", err)
	}
	if urlErr.code != BMOErrorURLFetchFailed {
		t.Errorf("error code = %d, want %d", urlErr.code, BMOErrorURLFetchFailed)
	}
}

func TestBMODeviceMetaURLModeEndToEnd(t *testing.T) {
	// Actual image data
	imageData := []byte("actual image content")
	imageHash := sha256.Sum256(imageData)
	imageURL := "https://cdn.example.com/image.bin"

	// Create meta-payload
	meta := MetaPayload{
		MIMEType:     "application/x-raw-disk-image",
		URL:          imageURL,
		HashAlg:      "sha256",
		ExpectedHash: imageHash[:],
		Name:         "test-image",
		BootArgs:     "console=ttyS0",
	}
	metaData, err := meta.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal meta-payload: %v", err)
	}

	metaURL := "https://vendor.example.com/meta.cbor"

	// Create mock fetcher
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			metaURL:  metaData,
			imageURL: imageData,
		},
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{
		returnStatus:  0,
		returnMessage: "success",
	}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler: handler,
		URLFetcher:     fetcher,
	}

	// Simulate receiving image-begin with meta-URL mode (unsigned)
	bmo.begin = chunking.BeginMessage{
		FSIMFields: map[int]any{
			-1: "application/x-bmo-meta",
			-6: uint64(DeliveryModeMetaURL),
			-7: metaURL,
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err = endFunc(chunking.EndMessage{})

	if err != nil {
		t.Fatalf("onEndUnified failed: %v", err)
	}

	// Verify both URLs were fetched
	if len(fetcher.fetchedURLs) != 2 {
		t.Fatalf("expected 2 URLs fetched, got %d", len(fetcher.fetchedURLs))
	}
	if fetcher.fetchedURLs[0] != metaURL {
		t.Errorf("first URL should be meta URL, got %q", fetcher.fetchedURLs[0])
	}
	if fetcher.fetchedURLs[1] != imageURL {
		t.Errorf("second URL should be image URL, got %q", fetcher.fetchedURLs[1])
	}

	// Verify the handler received the image with correct type from meta-payload
	if len(handler.receivedImages) != 1 {
		t.Fatalf("expected 1 image, got %d", len(handler.receivedImages))
	}

	img := handler.receivedImages[0]
	if img.imageType != "application/x-raw-disk-image" {
		t.Errorf("imageType should come from meta-payload, got %q", img.imageType)
	}
	if img.name != "test-image" {
		t.Errorf("name should come from meta-payload, got %q", img.name)
	}
	if !bytes.Equal(img.data, imageData) {
		t.Errorf("image data mismatch")
	}

	// Verify boot_args was passed in metadata
	if img.metadata == nil || img.metadata["boot_args"] != "console=ttyS0" {
		t.Errorf("boot_args should be in metadata, got %v", img.metadata)
	}
}

func TestBMODeviceMetaURLModeSignedPayload(t *testing.T) {
	// Actual image data
	imageData := []byte("actual image content")
	imageURL := "https://cdn.example.com/image.bin"

	// Create meta-payload
	meta := MetaPayload{
		MIMEType: "application/x-raw-disk-image",
		URL:      imageURL,
	}
	metaData, err := meta.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal meta-payload: %v", err)
	}

	metaURL := "https://vendor.example.com/meta.cbor"
	signerKey := []byte{0x01, 0x02, 0x03} // Fake signer key

	// Create mock fetcher
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			metaURL:  []byte("signed-wrapper-around-meta"), // Simulated signed payload
			imageURL: imageData,
		},
	}

	// Create mock verifier that returns the actual meta-payload
	verifier := &mockMetaPayloadVerifier{
		payload: metaData,
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{
		returnStatus:  0,
		returnMessage: "success",
	}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler:      handler,
		URLFetcher:          fetcher,
		MetaPayloadVerifier: verifier,
	}

	// Simulate receiving image-begin with meta-URL mode (signed)
	bmo.begin = chunking.BeginMessage{
		FSIMFields: map[int]any{
			-1:  "application/x-bmo-meta",
			-6:  uint64(DeliveryModeMetaURL),
			-7:  metaURL,
			-10: signerKey,
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err = endFunc(chunking.EndMessage{})

	if err != nil {
		t.Fatalf("onEndUnified failed: %v", err)
	}

	// Verify the handler received the image
	if len(handler.receivedImages) != 1 {
		t.Fatalf("expected 1 image, got %d", len(handler.receivedImages))
	}

	img := handler.receivedImages[0]
	if img.imageType != "application/x-raw-disk-image" {
		t.Errorf("imageType should come from meta-payload, got %q", img.imageType)
	}
}

func TestBMODeviceMetaURLModeSignatureInvalid(t *testing.T) {
	metaURL := "https://vendor.example.com/meta.cbor"
	signerKey := []byte{0x01, 0x02, 0x03}

	// Create mock fetcher
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			metaURL: []byte("signed-payload"),
		},
	}

	// Create mock verifier that returns an error
	verifier := &mockMetaPayloadVerifier{
		verifyErr: errors.New("signature verification failed"),
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler:      handler,
		URLFetcher:          fetcher,
		MetaPayloadVerifier: verifier,
	}

	// Simulate receiving image-begin with meta-URL mode (signed)
	bmo.begin = chunking.BeginMessage{
		FSIMFields: map[int]any{
			-1:  "application/x-bmo-meta",
			-6:  uint64(DeliveryModeMetaURL),
			-7:  metaURL,
			-10: signerKey,
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err := endFunc(chunking.EndMessage{})

	// Should return an error
	if err == nil {
		t.Fatal("expected error for signature verification failure, got nil")
	}

	// Verify it's a bmoURLError with correct code
	urlErr, ok := err.(*bmoURLError)
	if !ok {
		t.Fatalf("expected *bmoURLError, got %T", err)
	}
	if urlErr.code != BMOErrorMetaSignatureInvalid {
		t.Errorf("error code = %d, want %d", urlErr.code, BMOErrorMetaSignatureInvalid)
	}
}

func TestBMODeviceMetaURLModeParseError(t *testing.T) {
	metaURL := "https://vendor.example.com/meta.cbor"

	// Create mock fetcher that returns invalid CBOR
	fetcher := &mockURLFetcher{
		data: map[string][]byte{
			metaURL: []byte("not valid cbor"),
		},
	}

	// Create mock handler
	handler := &mockUnifiedImageHandler{}

	// Create BMO device
	bmo := &BMO{
		UnifiedHandler: handler,
		URLFetcher:     fetcher,
	}

	// Simulate receiving image-begin with meta-URL mode (unsigned)
	bmo.begin = chunking.BeginMessage{
		FSIMFields: map[int]any{
			-1: "application/x-bmo-meta",
			-6: uint64(DeliveryModeMetaURL),
			-7: metaURL,
		},
	}
	bmo.buffer = &bytes.Buffer{}

	// Call onEndUnified
	ctx := context.Background()
	endFunc := bmo.onEndUnified(ctx)
	err := endFunc(chunking.EndMessage{})

	// Should return an error
	if err == nil {
		t.Fatal("expected error for meta-payload parse failure, got nil")
	}

	// Verify it's a bmoURLError with correct code
	urlErr, ok := err.(*bmoURLError)
	if !ok {
		t.Fatalf("expected *bmoURLError, got %T", err)
	}
	if urlErr.code != BMOErrorMetaParseError {
		t.Errorf("error code = %d, want %d", urlErr.code, BMOErrorMetaParseError)
	}
}

func TestDeliveryModeConstants(t *testing.T) {
	// Verify constants match spec
	if DeliveryModeInline != 0 {
		t.Errorf("DeliveryModeInline = %d, want 0", DeliveryModeInline)
	}
	if DeliveryModeURL != 1 {
		t.Errorf("DeliveryModeURL = %d, want 1", DeliveryModeURL)
	}
	if DeliveryModeMetaURL != 2 {
		t.Errorf("DeliveryModeMetaURL = %d, want 2", DeliveryModeMetaURL)
	}
}

func TestBMOErrorCodeConstants(t *testing.T) {
	// Verify error codes match spec
	if BMOErrorURLFetchFailed != 9 {
		t.Errorf("BMOErrorURLFetchFailed = %d, want 9", BMOErrorURLFetchFailed)
	}
	if BMOErrorTLSValidationFailed != 10 {
		t.Errorf("BMOErrorTLSValidationFailed = %d, want 10", BMOErrorTLSValidationFailed)
	}
	if BMOErrorHashMismatch != 11 {
		t.Errorf("BMOErrorHashMismatch = %d, want 11", BMOErrorHashMismatch)
	}
	if BMOErrorMetaSignatureInvalid != 12 {
		t.Errorf("BMOErrorMetaSignatureInvalid = %d, want 12", BMOErrorMetaSignatureInvalid)
	}
	if BMOErrorMetaParseError != 13 {
		t.Errorf("BMOErrorMetaParseError = %d, want 13", BMOErrorMetaParseError)
	}
	if BMOErrorDeliveryModeNotSupported != 14 {
		t.Errorf("BMOErrorDeliveryModeNotSupported = %d, want 14", BMOErrorDeliveryModeNotSupported)
	}
}
