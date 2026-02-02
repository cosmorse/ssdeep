package ssdeep

import (
	"testing"
)

func TestHashBytes(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	hash, err := HashBytes(data)
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

	h1, _ := HashBytes([]byte(s1))
	h2, _ := HashBytes([]byte(s2))
	h3, _ := HashBytes([]byte(s3))

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
	h1, _ := HashBytes([]byte(""))
	h2, _ := HashBytes([]byte(""))
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

	h1, _ := HashBytes(data1)
	h2, _ := HashBytes(data2)

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
		_, _ = HashBytes(data)
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
		_, _ = HashBytes(data)
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
		_, _ = HashBytes(data)
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

	h1, _ := HashBytes(data1)
	h2, _ := HashBytes(data2)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Compare(h1, h2)
	}
}
