// Package ssdeep implements the ssdeep fuzzy hashing algorithm.
// This algorithm computes fuzzy hashes for files, enabling similarity detection
// even when files have minor differences.
package ssdeep

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// minBlockSize is the smallest chunk size used in ssdeep algorithm (minimum 3)
	minBlockSize = 3
	// windowSize is the sliding window size used in rolling hash calculations (typically 7)
	windowSize = 7
	// spamSumLength is the maximum length of hash segments (typically 64 characters)
	spamSumLength = 64
	// base64Chars is the character set used for hash output encoding
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// hashInit is the initial value for piecewise hash (compatible with official implementation)
	hashInit = 0x01234567
)

var (
	ErrEmptyData = fmt.Errorf("ssdeep: empty data")
)

type hashOptions struct {
	size int64
}

type Option interface {
	apply(*hashOptions)
}

type sizeOption int64

func (o sizeOption) apply(h *hashOptions) {
	if o > 0 {
		h.size = int64(o)
	}
}

func WithFixedSize(size int64) Option {
	return sizeOption(size)
}

// ssdeepState stores the intermediate state for hash calculation
// This structure maintains rolling hash (for detecting boundaries) and piecewise hash (for generating digest characters)
// along with buffers for hash generation. Fields:
//   - blockSize: basic chunk size for this hash (estimated from input length)
//   - h1/h2/h3: three components of rolling hash (see Write for specific update rules)
//   - window: stores recent windowSize bytes to maintain h1 sliding window
//   - n: total processed bytes count (for window indexing)
//   - p1/p2: current piecewise hash states for blockSize and blockSize*2 respectively
//   - res1/res2: string digest results for two scales (mapped to base64Chars characters)
type ssdeepState struct {
	blockSize uint32 // Current chunk size used

	// Rolling hash state
	h1, h2, h3 uint32           // Three components of rolling hash
	window     [windowSize]byte // Sliding window buffer
	n          uint32           // Number of bytes processed, used for window index

	// Piecewise hash state
	p1 uint32 // Piecewise hash value for blockSize
	p2 uint32 // Piecewise hash value for blockSize * 2

	// Result buffer
	res1 []byte // Hash string corresponding to blockSize
	res2 []byte // Hash string corresponding to blockSize * 2
}

// newSSDeepState initializes a new ssdeepState
// Initialization details:
//   - p1/p2 initialized to hashInit (initial value for piecewise hash);
//   - res1/res2 pre-allocated to avoid frequent expansion;
//   - blockSize passed from upper layer to make output digest close to target length (see estimateBlockSize).
func newSSDeepState(blockSize uint32) *ssdeepState {
	return &ssdeepState{
		blockSize: blockSize,
		p1:        hashInit,
		p2:        hashInit,
		res1:      make([]byte, 0, spamSumLength+1),
		res2:      make([]byte, 0, spamSumLength+1),
	}
}

// Write processes the input byte stream and updates the hash state.
// It maintains both rolling hash (for determining chunk boundaries) and piecewise hash (for calculating block content digests).
func (s *ssdeepState) Write(p []byte) (n int, err error) {
	bs1 := s.blockSize
	bs2 := bs1 * 2
	h1, h2, h3 := s.h1, s.h2, s.h3
	p1, p2 := s.p1, s.p2
	n_idx := s.n

	for _, c := range p {
		u_c := uint32(c)

		// Rolling hash update (three components):
		// 	- h1 represents sum of window bytes (maintained by adding new byte and removing oldest byte)
		// 	- h2 accumulates h1 over time, providing temporal diffusion for boundary triggering
		// 	- h3 introduces bit mixing through left shift and XOR with new byte for better randomness
		// Specific update form comes from original implementation, proven in practice to closely match official behavior:
		h2 -= h1
		h2 += windowSize * u_c

		h1 += u_c
		h1 -= uint32(s.window[n_idx%windowSize])

		s.window[n_idx%windowSize] = c
		n_idx++

		h3 <<= 5
		h3 ^= u_c

		// Piecewise hash update (similar to FNV with multiply then XOR) to match official implementation: p = (p * FNV_PRIME) ^ c
		// Uses p = (p * FNV_PRIME) ^ c, will map p to a 6-bit character when boundary is encountered
		// to generate digest characters. The 16777619 is the common FNV prime.
		p1 = (p1 * 16777619) ^ u_c
		p2 = (p2 * 16777619) ^ u_c

		h := h1 + h2 + h3

		// Check if first chunk boundary reached (blockSize)
		if h%bs1 == (bs1 - 1) {
			if len(s.res1) < spamSumLength {
				s.res1 = append(s.res1, base64Chars[p1%64])
			}
			p1 = hashInit // Reset piecewise hash to process next chunk
		}

		// Check if second chunk boundary reached (blockSize * 2)
		if h%bs2 == (bs2 - 1) {
			if len(s.res2) < spamSumLength {
				s.res2 = append(s.res2, base64Chars[p2%64])
			}
			p2 = hashInit
		}
	}

	// 将局部变量写回结构体状态
	s.h1, s.h2, s.h3 = h1, h2, h3
	s.p1, s.p2 = p1, p2
	s.n = n_idx

	return len(p), nil
}

// Compare calculates similarity score (0 to 100) between two ssdeep hash values.
// Score of 100 means completely identical, 0 means no significant similarity.
func Compare(hash1, hash2 string) (int, error) {
	p1 := strings.Split(hash1, ":")
	p2 := strings.Split(hash2, ":")
	if len(p1) != 3 || len(p2) != 3 {
		return 0, fmt.Errorf("invalid hash format")
	}

	var b1, b2 uint32
	fmt.Sscanf(p1[0], "%d", &b1)
	fmt.Sscanf(p2[0], "%d", &b2)
	s1_1, s1_2 := p1[1], p1[2]
	s2_1, s2_2 := p2[1], p2[2]

	// 块大小必须相等，或者成 2 倍关系
	if b1 != b2 && b1 != b2*2 && b2 != b1*2 {
		return 0, nil
	}

	if b1 == b2 {
		// 比较相同块大小的部分
		score1 := score(s1_1, s2_1)
		score2 := score(s1_2, s2_2)
		if score1 > score2 {
			return score1, nil
		}
		return score2, nil
	} else if b1 == b2*2 {
		// 比较 hash1 的第一部分和 hash2 的第二部分
		return score(s1_1, s2_2), nil
	} else {
		// 比较 hash1 的第二部分和 hash2 的第一部分
		return score(s1_2, s2_1), nil
	}
}

// score calculates similarity between two hash segment strings using an official-compatible algorithm:
//   - Preprocess strings with shrink (compress repeated characters)
//   - Repeatedly find longest common substrings of length >= 3 and remove them
//   - Count matching characters and calculate score using official formula
func score(s1, s2 string) int {
	if s1 == s2 {
		return 100
	}

	// 预处理：压缩连续超过 3 个的相同字符（ssdeep 规范）
	s1 = shrink(s1)
	s2 = shrink(s2)

	n1 := len(s1)
	n2 := len(s2)
	if n1 == 0 || n2 == 0 {
		return 0
	}

	matches := 0
	for {
		l, ia, ib := findLongestCommonSubstring(s1, s2, 3)
		if l < 3 {
			break
		}
		matches += l
		// 从两个字符串中移除已匹配的子串以避免重复计数
		s1 = s1[:ia] + s1[ia+l:]
		s2 = s2[:ib] + s2[ib+l:]
		if len(s1) < 3 || len(s2) < 3 {
			break
		}
	}

	if matches == 0 {
		return 0
	}

	// 使用官方公式：score = round(200 * matches / (len1 + len2))，并限制在 0..100
	scoreF := int(float64(matches*200)/float64(n1+n2) + 0.5)
	if scoreF > 100 {
		scoreF = 100
	}
	return scoreF
}

// shrink compresses characters that repeat consecutively more than 3 times, which is part of ssdeep similarity algorithm
func shrink(s string) string {
	if len(s) <= 3 {
		return s
	}
	res := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		// Skip if current character is the same as the previous three characters
		if i < 3 || s[i] != s[i-1] || s[i] != s[i-2] || s[i] != s[i-3] {
			res = append(res, s[i])
		}
	}
	return string(res)
}

// findLongestCommonSubstring finds the longest common substring in a, b with length at least minLen,
// returns (length, position in a, position in b).
// This function is used in the similarity calculation algorithm to find matching patterns between two hash strings.
func findLongestCommonSubstring(a, b string, minLen int) (int, int, int) {
	na := len(a)
	nb := len(b)
	maxL := na
	if nb < maxL {
		maxL = nb
	}
	for L := maxL; L >= minLen; L-- {
		seen := make(map[string]int)
		for i := 0; i+L <= na; i++ {
			seen[a[i:i+L]] = i
		}
		for j := 0; j+L <= nb; j++ {
			if ia, ok := seen[b[j:j+L]]; ok {
				return L, ia, j
			}
		}
	}
	return 0, 0, 0
}

// Sum returns the final generated ssdeep hash string in format "blockSize:hash1:hash2"
func (s *ssdeepState) Sum() string {
	// Process remaining data even if no boundary was reached
	r1 := s.res1
	if s.p1 != hashInit && len(r1) < spamSumLength {
		r1 = append(r1, base64Chars[s.p1%64])
	}
	r2 := s.res2
	if s.p2 != hashInit && len(r2) < spamSumLength {
		r2 = append(r2, base64Chars[s.p2%64])
	}

	return fmt.Sprintf("%d:%s:%s", s.blockSize, string(r1), string(r2))
}

// sumWithFixedSize processes data stream with a fixed size, using the correct block size
func sumWithFixedSize(r io.Reader, fixedSize int64) (string, error) {
	if fixedSize <= 0 {
		return "", ErrEmptyData
	}

	// Use the known size to set the correct block size
	blockSize := estimateBlockSize(fixedSize)
	state := newSSDeepState(blockSize)
	_, err := io.Copy(state, r)
	if err != nil {
		return "", err
	}
	return state.Sum(), nil
}

// Bytes computes the ssdeep fuzzy hash for a given byte slice.
func Bytes(data []byte) (string, error) {
	if len(data) == 0 {
		// Return a default empty hash representation instead of error
		// Following the original ssdeep convention for empty data
		blockSize := estimateBlockSize(0)
		return fmt.Sprintf("%d::", blockSize), nil
	}

	return sumWithFixedSize(bytes.NewReader(data), int64(len(data)))
}

// File computes the ssdeep fuzzy hash for a file at the given path.
func File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return Stream(file)
}

type statReader interface {
	io.Reader
	Stat() (os.FileInfo, error)
}

// Stream computes the ssdeep fuzzy hash from an io.Reader.
// For objects implementing io.ReadSeeker (like files), it pre-fetches the size for optimal block size.
// For regular Readers, it tries to determine the size when possible, or estimates block size from initial data.
func Stream(r io.Reader, options ...Option) (string, error) {
	var opts = hashOptions{size: -1}
	for _, o := range options {
		o.apply(&opts)
	}

	if opts.size <= 0 {
		if ri, ok := r.(statReader); ok {
			info, err := ri.Stat()
			if err != nil {
				return "", err
			}

			opts.size = info.Size()
		} else if rs, ok := r.(io.ReadSeeker); ok {
			size, err := rs.Seek(0, io.SeekEnd)
			if err != nil {
				return "", err
			}

			if _, err = rs.Seek(0, io.SeekStart); err != nil {
				return "", err
			}

			opts.size = size
		}
	}

	if opts.size >= 0 {
		return sumWithFixedSize(r, opts.size)
	}

	// 对于普通Reader，我们需要估算合适的块大小
	// 因为我们无法预先知道总大小（并且不能重置流）
	//
	// 解决方案：使用分块读取的方式，在读取过程中估算大小
	const chunkSize = 64 * 1024 // 64KB chunks
	buffer := make([]byte, chunkSize)

	// 读取第一块数据来估算大小
	n, err := r.Read(buffer)
	if err == io.EOF {
		// 数据很少，直接处理
		blockSize := estimateBlockSize(int64(n))
		state := newSSDeepState(blockSize)
		_, writeErr := state.Write(buffer[:n])
		if writeErr != nil {
			return "", writeErr
		}
		return state.Sum(), nil
	}
	if err != nil && err != io.EOF {
		return "", err
	}

	// 基于已读取的数据估算总大小
	// 如果第一块是满的，我们假设还有更多数据
	var estimatedTotalSize int64
	if n == chunkSize {
		// 如果第一块是满的，假设实际大小是当前的2-4倍（启发式方法）
		estimatedTotalSize = int64(n) * 4
	} else {
		// 如果第一块不满，这就是全部数据
		estimatedTotalSize = int64(n)
	}

	// 使用估算的大小创建状态
	blockSize := estimateBlockSize(estimatedTotalSize)
	state := newSSDeepState(blockSize)

	// 处理第一块数据
	_, writeErr := state.Write(buffer[:n])
	if writeErr != nil {
		return "", writeErr
	}

	// 继续处理剩余数据
	for {
		n, err := r.Read(buffer)
		if n > 0 {
			_, writeErr := state.Write(buffer[:n])
			if writeErr != nil {
				return "", writeErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return state.Sum(), nil
}

// estimateBlockSize estimates the initial block size based on total data size, aiming to make the resulting hash length approach 64 characters.
// This is crucial for ssdeep algorithm as the block size determines how frequently digest characters are generated.
// The formula ensures that blockSize * spamSumLength (64) is approximately equal to or greater than the data size,
// which helps generate hashes of reasonable length for similarity comparisons.
func estimateBlockSize(size int64) uint32 {
	blockSize := uint32(minBlockSize)
	for uint64(blockSize)*spamSumLength < uint64(size) {
		blockSize *= 2
	}
	return blockSize
}
