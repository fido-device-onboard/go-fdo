// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto/elliptic"
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
				DeliveryMode: uint(tt.deliveryMode),
				FSIMFields: map[int]any{
					-1: "application/x-iso9660-image",
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
		HashAlg:      "sha256",
		DeliveryMode: DeliveryModeURL,
		URL:          imageURL,
		ExpectedHash: imageHash[:],
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
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
		HashAlg:      "sha256",
		DeliveryMode: DeliveryModeURL,
		URL:          imageURL,
		ExpectedHash: wrongHash,
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
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

	assertTransferCode(t, err, BMOErrorHashMismatch)

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
		DeliveryMode: DeliveryModeURL,
		URL:          "https://example.com/image.bin",
		ExpectedHash: make([]byte, 32), // pinned, so the fetch is attempted
		FSIMFields: map[int]any{
			-1: "application/x-iso9660-image",
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

	assertTransferCode(t, err, BMOErrorURLFetchFailed)
}

// metaTestSetup builds a device, an image at imageURL, and a fetcher that
// serves metaBody at metaURL.
func metaTestSetup(metaBody []byte) (*BMO, *mockUnifiedImageHandler, *mockURLFetcher, []byte, string) {
	imageData := []byte("actual image content")
	imageURL := "https://cdn.example.com/image.bin"
	fetcher := &mockURLFetcher{data: map[string][]byte{
		"https://vendor.example.com/meta.cbor": metaBody,
		imageURL:                               imageData,
	}}
	handler := &mockUnifiedImageHandler{returnStatus: 0, returnMessage: "success"}
	bmo := &BMO{UnifiedHandler: handler, URLFetcher: fetcher, buffer: &bytes.Buffer{}}
	return bmo, handler, fetcher, imageData, imageURL
}

func metaBegin(beginHash, metaSigner []byte) chunking.BeginMessage {
	return chunking.BeginMessage{
		HashAlg:      "sha256",
		DeliveryMode: DeliveryModeMetaURL,
		URL:          "https://vendor.example.com/meta.cbor",
		ExpectedHash: beginHash,
		MetaSigner:   metaSigner,
		FSIMFields:   map[int]any{-1: "application/x-bmo-meta"},
	}
}

// Signed by a named third-party publisher (meta_signer, key 9): accepted, and
// its instruction fields (boot_args) are honoured.
func TestBMODeviceMetaURLModeSignedPayload(t *testing.T) {
	priv, coseKey := generateTestKey(t, elliptic.P256())
	imageHash := sha256.Sum256([]byte("actual image content"))
	meta := MetaPayload{
		MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin",
		HashAlg: "sha256", ExpectedHash: imageHash[:], Name: "test-image", BootArgs: "console=ttyS0",
	}
	metaCBOR, _ := meta.MarshalCBOR()
	signed, err := SignMetaPayload(metaCBOR, priv)
	if err != nil {
		t.Fatal(err)
	}
	bmo, handler, fetcher, imageData, imageURL := metaTestSetup(signed)
	bmo.begin = metaBegin(nil, coseKey)

	if err := bmo.onEndUnified(context.Background())(chunking.EndMessage{}); err != nil {
		t.Fatalf("onEndUnified failed: %v", err)
	}
	if len(fetcher.fetchedURLs) != 2 || fetcher.fetchedURLs[1] != imageURL {
		t.Fatalf("unexpected fetches: %v", fetcher.fetchedURLs)
	}
	img := handler.receivedImages[0]
	if img.imageType != "application/x-raw-disk-image" || img.name != "test-image" || !bytes.Equal(img.data, imageData) {
		t.Errorf("image fields not taken from the signed meta-payload: %+v", img)
	}
	if img.metadata["boot_args"] != "console=ttyS0" {
		t.Errorf("boot_args from an authenticated meta-payload should be passed through, got %v", img.metadata)
	}
}

// Named publisher, but the meta-payload is signed by a different key: 12.
func TestBMODeviceMetaURLModeSignatureInvalid(t *testing.T) {
	signerPriv, _ := generateTestKey(t, elliptic.P256())
	_, otherKey := generateTestKey(t, elliptic.P256())
	meta := MetaPayload{MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin"}
	metaCBOR, _ := meta.MarshalCBOR()
	signed, _ := SignMetaPayload(metaCBOR, signerPriv)
	bmo, handler, _, _, _ := metaTestSetup(signed)
	bmo.begin = metaBegin(nil, otherKey)

	err := bmo.onEndUnified(context.Background())(chunking.EndMessage{})
	assertTransferCode(t, err, BMOErrorMetaSignatureInvalid)
	if len(handler.receivedImages) != 0 {
		t.Error("image must not be delivered")
	}
}

// meta_signer named but the meta-payload is unsigned: never downgraded, 12.
func TestBMODeviceMetaURLModeSignerNamedButUnsigned(t *testing.T) {
	_, coseKey := generateTestKey(t, elliptic.P256())
	meta := MetaPayload{MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin"}
	metaCBOR, _ := meta.MarshalCBOR()
	bmo, _, _, _, _ := metaTestSetup(metaCBOR)
	bmo.begin = metaBegin(nil, coseKey)
	assertTransferCode(t, bmo.onEndUnified(context.Background())(chunking.EndMessage{}), BMOErrorMetaSignatureInvalid)
}

// Unsigned meta-payload, not over validated TLS, no hash pinned in
// image-begin: nothing authenticates the image. Refused with 19, and the
// image is never downloaded. (This was previously accepted.)
func TestBMODeviceMetaURLModeUnauthenticatedRefused(t *testing.T) {
	imageHash := sha256.Sum256([]byte("actual image content"))
	meta := MetaPayload{MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin",
		HashAlg: "sha256", ExpectedHash: imageHash[:]}
	metaCBOR, _ := meta.MarshalCBOR()
	bmo, handler, fetcher, _, _ := metaTestSetup(metaCBOR)
	bmo.begin = metaBegin(nil, nil)

	err := bmo.onEndUnified(context.Background())(chunking.EndMessage{})
	assertTransferCode(t, err, BMOErrorUnauthenticatedSource)
	if len(fetcher.fetchedURLs) != 1 || len(handler.receivedImages) != 0 {
		t.Errorf("only the meta-payload should have been fetched; fetched=%v", fetcher.fetchedURLs)
	}
}

// Unsigned meta-payload used as a pointer: image-begin pins the image hash,
// the meta-payload carries only pointer/constraint/informational fields.
// Accepted.
func TestBMODeviceMetaURLModeUnauthenticatedPointer(t *testing.T) {
	imageHash := sha256.Sum256([]byte("actual image content"))
	meta := MetaPayload{MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin",
		HashAlg: "sha256", ExpectedHash: imageHash[:], Name: "n"}
	metaCBOR, _ := meta.MarshalCBOR()
	bmo, handler, _, imageData, _ := metaTestSetup(metaCBOR)
	bmo.begin = metaBegin(imageHash[:], nil)

	if err := bmo.onEndUnified(context.Background())(chunking.EndMessage{}); err != nil {
		t.Fatalf("pointer-only meta-payload with pinned image hash should be accepted: %v", err)
	}
	if !bytes.Equal(handler.receivedImages[0].data, imageData) {
		t.Error("image data mismatch")
	}
}

// Unsigned meta-payload carrying boot_args: refused with 15 even though the
// image hash is pinned — a kernel command line takes over the device without
// changing the image.
func TestBMODeviceMetaURLModeUnauthenticatedBootArgsRefused(t *testing.T) {
	imageHash := sha256.Sum256([]byte("actual image content"))
	meta := MetaPayload{MIMEType: "application/x-raw-disk-image", URL: "https://cdn.example.com/image.bin",
		BootArgs: "init=/bin/sh"}
	metaCBOR, _ := meta.MarshalCBOR()
	bmo, handler, _, _, _ := metaTestSetup(metaCBOR)
	bmo.begin = metaBegin(imageHash[:], nil)

	assertTransferCode(t, bmo.onEndUnified(context.Background())(chunking.EndMessage{}), BMOErrorProvisionNotAuthorized)
	if len(handler.receivedImages) != 0 {
		t.Error("image must not be delivered")
	}
}

// URL mode without a hash and a fetcher that cannot validate TLS: refused
// with 19 before downloading.
func TestBMODeviceURLModeNoHashRefused(t *testing.T) {
	fetcher := &mockURLFetcher{data: map[string][]byte{"https://example.com/image.bin": []byte("x")}}
	bmo := &BMO{UnifiedHandler: &mockUnifiedImageHandler{}, URLFetcher: fetcher, buffer: &bytes.Buffer{}}
	bmo.begin = chunking.BeginMessage{DeliveryMode: DeliveryModeURL, URL: "https://example.com/image.bin",
		FSIMFields: map[int]any{-1: "application/x-iso9660-image"}}

	assertTransferCode(t, bmo.onEndUnified(context.Background())(chunking.EndMessage{}), BMOErrorUnauthenticatedSource)
	if len(fetcher.fetchedURLs) != 0 {
		t.Error("nothing should be downloaded when the content cannot be authenticated")
	}
}

func assertTransferCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %d, got nil", want)
	}
	var te *chunking.TransferError
	if !errors.As(err, &te) {
		t.Fatalf("expected *chunking.TransferError, got %T: %v", err, err)
	}
	if te.Code != want {
		t.Errorf("error code = %d, want %d (%v)", te.Code, want, err)
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
		DeliveryMode: DeliveryModeMetaURL,
		URL:          metaURL,
		FSIMFields: map[int]any{
			-1: "application/x-bmo-meta",
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

	assertTransferCode(t, err, BMOErrorMetaParseError)
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
