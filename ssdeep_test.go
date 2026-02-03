package ssdeep

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashBytes(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	hash, err := Bytes(data)
	if err != nil {
		t.Fatalf("HashBytes failed: %v", err)
	}
	t.Logf("Hash: %s", hash)
	if hash == "" {
		t.Fatal("Hash is empty")
	}
}

func TestCompare(t *testing.T) {
	s1 := "The quick brown fox jumps over the lazy dog"
	s2 := "The quick brown fox jumps over the lazy dog!"
	s3 := "A completely different string that should have no similarity"

	h1, _ := Bytes([]byte(s1))
	h2, _ := Bytes([]byte(s2))
	h3, _ := Bytes([]byte(s3))

	score12, err := Compare(h1, h2)
	if err != nil {
		t.Fatalf("Compare h1-h2 failed: %v", err)
	}
	t.Logf("Score h1-h2: %d", score12)
	if score12 < 50 {
		t.Errorf("Expected high similarity between s1 and s2, got %d", score12)
	}

	score13, err := Compare(h1, h3)
	if err != nil {
		t.Fatalf("Compare h1-h3 failed: %v", err)
	}
	t.Logf("Score h1-h3: %d", score13)
	if score13 > 40 { // Increased threshold for short strings
		t.Errorf("Expected low similarity between s1 and s3, got %d", score13)
	}

	score11, _ := Compare(h1, h1)
	if score11 != 100 {
		t.Errorf("Expected score 100 for identical hashes, got %d", score11)
	}
}

func TestEmpty(t *testing.T) {
	h1, _ := Bytes([]byte(""))
	h2, _ := Bytes([]byte(""))
	score, _ := Compare(h1, h2)
	if score != 100 {
		t.Errorf("Expected score 100 for empty strings, got %d", score)
	}
}

func TestLargeSimilarity(t *testing.T) {
	data1 := make([]byte, 10000)
	for i := range data1 {
		data1[i] = byte(i % 256)
	}
	data2 := make([]byte, 10000)
	copy(data2, data1)
	data2[5000] = data2[5000] ^ 0xFF // Change one byte

	h1, _ := Bytes(data1)
	h2, _ := Bytes(data2)

	t.Logf("h1: %s", h1)
	t.Logf("h2: %s", h2)

	score, _ := Compare(h1, h2)
	t.Logf("Large data score: %d", score)
	if score < 90 {
		t.Errorf("Expected high score for large similar data, got %d", score)
	}
}

func BenchmarkHashBytes1K(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Bytes(data)
	}
}

func BenchmarkHashBytes64K(b *testing.B) {
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Bytes(data)
	}
}

func BenchmarkHashBytes1M(b *testing.B) {
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Bytes(data)
	}
}

func BenchmarkHashBytes10M(b *testing.B) {
	data := make([]byte, 10*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Bytes(data)
	}
}

func BenchmarkCompare(b *testing.B) {
	data1 := make([]byte, 10000)
	for i := range data1 {
		data1[i] = byte(i % 256)
	}
	data2 := make([]byte, 10000)
	copy(data2, data1)
	data2[5000] = data2[5000] ^ 0xFF

	h1, _ := Bytes(data1)
	h2, _ := Bytes(data2)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Compare(h1, h2)
	}
}

func TestHash(t *testing.T) {
	data := make([]byte, 10<<20)
	_, err := rand.Read(data)
	require.NoError(t, err)
	blockSize := estimateBlockSize(int64(len(data)))
	state := newSSDeepState(blockSize)
	_, err = state.Write(data)
	require.NoError(t, err)
	t.Log(state.Sum())
}

func TestHashAgainstOfficialAlgorithm(t *testing.T) {
	tests := []struct {
		path         string
		text         string
		expectedHash string
	}{
		{
			text:         "The quick brown fox jumps over the lazy dog",
			expectedHash: "3:FJKKIUKacdn:FHIGM",
		},
		{
			text:         "A completely different string that should have no similarity",
			expectedHash: "3:M3+4CDTfWRcyNEqrBFWMEWM8Xh:M3KDKKqzZEL8Xh",
		},
		{
			path:         "testdata/sample",
			expectedHash: "196608:m3SuutoWSz3nONRfeuYzllWVa7KqNoweSDLft2SOQp1fy/x7ri:mbuQznoRfepzllWABp1fy/g",
		},
	}

	for _, tc := range tests {
		var (
			data []byte
			hash string
			err  error
		)

		if tc.path != "" {
			data, err = os.ReadFile(tc.path)
			require.NoError(t, err, "Reading file failed for %s", tc.path)
		} else {
			data = []byte(tc.text)
		}
		hash, err = Bytes(data)
		require.NoError(t, err, "Hashing failed for %s", tc.text)
		require.Equal(t, tc.expectedHash, hash, "Hash mismatch for %s", tc.text)
	}
}

func TestCompareAgainstOfficialAlgorithm(t *testing.T) {
	tests := []struct {
		h1    string
		h2    string
		score int
	}{
		{
			h1:    "3:FJKKIUKact:FHIGi",
			h2:    "3:FJKKIUKact:FHIGi",
			score: 100,
		},
		{
			// Official score for these two is usually 71
			h1:    "3:FJKKIUKact:FHIGi",
			h2:    "3:FJKKIrKact:FHIrGi",
			score: 71,
		},
		{
			h1:    "48:xR7mN7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p:xR7mN7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p",
			h2:    "96:xR7mN7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p:xR7mN7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p",
			score: 100,
		},
		{
			h1:    "3:FJKKIUKact:FHIGi",
			h2:    "3:AXA:B",
			score: 0,
		},
		{
			// Block size ratio 1:2
			h1:    "12:hAnzB9Wp8+3vE+vP:hAnzhWp8jvE+vP",
			h2:    "24:hAnzhWp8jvE+vP:hAnzhWp8jvE+vP",
			score: 100,
		},
		{
			h1:    "49152:5AM11NN999r//99tt55JJtt0JCh9ZtB5FJB1BXh9ZtB5FJB1EpNajPZtLJXJvJ7x:PWDwVRXqpl5P0ncpK5WKFfwvSAvUl",
			h2:    "49152:SAM11NN999r//99tt55JJtt0JCh9ZtB5FJB1BXh9ZtB5FJB1EpNajPZtLJXJvJ7n:SWDwVRXqpl5P0ncpK5WKFfwvSAvUb",
			score: 97,
		},
	}

	for _, tc := range tests {
		s, err := Compare(tc.h1, tc.h2)
		require.NoError(t, err, "Compare failed for %s vs %s", tc.h1, tc.h2)
		require.Equal(t, tc.score, s, "Score mismatch for %s vs %s", tc.h1, tc.h2)
	}
}
