package ssdeep

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStreamReaderMemoryCache(t *testing.T) {
	data := []byte("Hello, this is a small test string")
	reader := strings.NewReader(string(data))

	sr := newStreamReader(reader, defaultCachedSize, true)
	defer sr.Close()

	// Read all data
	err := sr.ReadAll()
	require.NoError(t, err)
	require.Equal(t, int64(len(data)), sr.Size())
	require.False(t, sr.file != nil, "Should use memory for small data")

	// Reset and read back
	err = sr.Reset()
	require.NoError(t, err)

	result, err := io.ReadAll(sr)
	require.NoError(t, err)
	require.Equal(t, data, result)
}

func TestStreamReaderFileCache(t *testing.T) {
	// Create data larger than minCachedSize
	dataSize := int(minCachedSize) + 1024
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}
	reader := bytes.NewReader(data)

	sr := newStreamReader(reader, minCachedSize, true)
	defer sr.Close()

	// Read all data
	err := sr.ReadAll()
	require.NoError(t, err)
	require.Equal(t, int64(dataSize), sr.Size())
	require.True(t, sr.file != nil, "Should use file for large data")

	// Reset and read back
	err = sr.Reset()
	require.NoError(t, err)

	result, err := io.ReadAll(sr)
	require.NoError(t, err)
	require.Equal(t, data, result)
}

func TestStreamHashWithMemoryCache(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	reader := bytes.NewReader(data)

	hash, err := Stream(reader)
	require.NoError(t, err)

	// Compare with Bytes function
	expectedHash, err := Bytes(data)
	require.NoError(t, err)
	require.Equal(t, expectedHash, hash)
}

func TestStreamHashWithFileCache(t *testing.T) {
	// Create large data
	dataSize := int(defaultCachedSize) + 1024*1024
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}
	reader := bytes.NewReader(data)

	hash, err := Stream(reader)
	require.NoError(t, err)

	// Compare with Bytes function
	expectedHash, err := Bytes(data)
	require.NoError(t, err)
	require.Equal(t, expectedHash, hash)
}

func TestStreamWithCustomCacheSize(t *testing.T) {
	data := make([]byte, 256*1024) // 256KB
	for i := range data {
		data[i] = byte(i % 256)
	}
	reader := bytes.NewReader(data)

	// Use small cache size to force file usage
	hash, err := Stream(reader, WithCachedSize(128*1024))
	require.NoError(t, err)

	// Compare with Bytes function
	expectedHash, err := Bytes(data)
	require.NoError(t, err)
	require.Equal(t, expectedHash, hash)
}

func BenchmarkStreamMemoryCache(b *testing.B) {
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_, _ = Stream(reader)
	}
}

func BenchmarkStreamFileCache(b *testing.B) {
	data := make([]byte, 8*1024*1024) // 8MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		_, _ = Stream(reader)
	}
}
