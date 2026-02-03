// Package ssdeep implements the ssdeep fuzzy hashing algorithm.
// This algorithm computes fuzzy hashes for files, enabling similarity detection
// even when files have minor differences.
package ssdeep

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
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

// WithFixedSize option allows specifying a fixed size for the hash.
func WithFixedSize(size int64) Option {
	return sizeOption(size)
}

var ssdeepStatePool = sync.Pool{
	New: func() any {
		return &ssdeepState{
			hash1: make([]byte, 0, spamSumLength+1),
			hash2: make([]byte, 0, spamSumLength+1),
		}
	},
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

	// Result hash buffer
	hash1 []byte // Hash string corresponding to blockSize
	hash2 []byte // Hash string corresponding to blockSize * 2
}

func (state *ssdeepState) reset(blockSize uint32) {
	h1, h2 := state.hash1[:0], state.hash2[:0]
	*state = ssdeepState{
		blockSize: blockSize,
		p1:        hashInit,
		p2:        hashInit,
		hash1:     h1,
		hash2:     h2,
	}
}

// newSSDeepState initializes a new ssdeepState
// Initialization details:
//   - p1/p2 initialized to hashInit (initial value for piecewise hash);
//   - hash1/hash2 pre-allocated to avoid frequent expansion;
//   - blockSize passed from upper layer to make output digest close to target length (see estimateBlockSize).
func newSSDeepState(blockSize uint32) *ssdeepState {
	state := ssdeepStatePool.Get().(*ssdeepState)
	state.reset(blockSize)
	return state
}

// Write processes the input byte stream and updates the hash state.
// It maintains both rolling hash (for determining chunk boundaries) and piecewise hash (for calculating block content digests).
func (state *ssdeepState) Write(p []byte) (n int, err error) {
	bs1 := state.blockSize
	bs2 := bs1 * 2
	h1, h2, h3 := state.h1, state.h2, state.h3
	p1, p2 := state.p1, state.p2
	n_idx := state.n
	winIdx := n_idx % windowSize

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
		h1 -= uint32(state.window[winIdx])

		state.window[winIdx] = c
		winIdx++
		if winIdx == windowSize {
			winIdx = 0
		}
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
		// Optimization: h % bs2 == bs2-1 implies h % bs1 == bs1-1 because bs2 = bs1 * 2
		if h%bs1 == (bs1 - 1) {
			if len(state.hash1) < spamSumLength {
				state.hash1 = append(state.hash1, base64Chars[p1%64])
			}
			p1 = hashInit // Reset piecewise hash to process next chunk

			// Check if second chunk boundary reached (blockSize * 2)
			if h%bs2 == (bs2 - 1) {
				if len(state.hash2) < spamSumLength {
					state.hash2 = append(state.hash2, base64Chars[p2%64])
				}
				p2 = hashInit
			}
		}
	}

	// Write local variables back to state struct
	state.h1, state.h2, state.h3 = h1, h2, h3
	state.p1, state.p2 = p1, p2
	state.n = n_idx

	return len(p), nil
}

// Sum returns the final generated ssdeep hash string in format "blockSize:hash1:hash2"
func (state *ssdeepState) Sum() string {
	// Process remaining data even if no boundary was reached
	r1 := state.hash1
	if state.p1 != hashInit && len(r1) < spamSumLength {
		r1 = append(r1, base64Chars[state.p1%64])
	}
	r2 := state.hash2
	if state.p2 != hashInit && len(r2) < spamSumLength {
		r2 = append(r2, base64Chars[state.p2%64])
	}

	hash := make([]byte, 0, len(r1)+len(r2)+20)
	hash = strconv.AppendInt(hash, int64(state.blockSize), 10)
	hash = append(hash, ':')
	hash = append(hash, r1...)
	hash = append(hash, ':')
	hash = append(hash, r2...)
	return string(hash)
}

func (state *ssdeepState) Close() error {
	ssdeepStatePool.Put(state)
	return nil
}

// Compare calculates similarity score (0 to 100) between two ssdeep hash values.
// Score of 100 means completely identical, 0 means no significant similarity.
func Compare(hash1, hash2 string) (int, error) {
	p1 := strings.Split(hash1, ":")
	p2 := strings.Split(hash2, ":")
	if len(p1) != 3 || len(p2) != 3 {
		return 0, fmt.Errorf("invalid hash format")
	}

	var (
		b1, b2 int
		err    error
	)

	if b1, err = strconv.Atoi(p1[0]); err != nil {
		return 0, err
	}

	if b2, err = strconv.Atoi(p2[0]); err != nil {
		return 0, err
	}

	s1_1, s1_2 := p1[1], p1[2]
	s2_1, s2_2 := p2[1], p2[2]

	// 块大小必须相等，或者成 2 倍关系
	if b1 != b2 && b1 != b2*2 && b2 != b1*2 {
		return 0, nil
	}

	switch b1 {
	case b2:
		// compare equal block size parts
		score1 := score(s1_1, s2_1, uint32(b1))
		score2 := score(s1_2, s2_2, uint32(b1*2))

		// Saturated hash rule: if both first parts are max length (64),
		// they are potentially truncated. Favor the second part if it matches.
		if len(s1_1) >= spamSumLength && len(s2_1) >= spamSumLength && score2 > 0 {
			return score2, nil
		}

		return max(score1, score2), nil
	case b2 * 2:
		// compare hash1 first part and hash2 second part
		return score(s1_1, s2_2, uint32(b1)), nil
	default:
		// compare hash1 second part and hash2 first part
		return score(s1_2, s2_1, uint32(b2)), nil
	}
}

// score calculates similarity between two hash segment strings using the official ssdeep algorithm:
//  1. Shrink strings
//  2. Calculate Levenshtein distance
//  3. Normalize distance to a score 0-100 and apply heuristics
func score(s1, s2 string, _ uint32) int {
	if s1 == s2 {
		return 100
	}

	// Use stack-allocated buffers for shrinking to avoid allocations
	var b1Buf, b2Buf [spamSumLength]byte
	b1 := shrink(s1, b1Buf[:0])
	b2 := shrink(s2, b2Buf[:0])

	n1 := len(b1)
	n2 := len(b2)

	// Official check: strings must have a minimum length
	if n1 < windowSize || n2 < windowSize {
		return 0
	}

	dist := levenshtein(b1, b2)

	// Official ssdeep formula
	s := uint32(dist) * spamSumLength / uint32(n1+n2)
	s = s * 100 / spamSumLength
	dist = 100 - int(s)

	// Short string penalty
	// This matches the official heuristic for strings shorter than 11 chars
	if n1 < 11 || n2 < 11 {
		limit := int(uint32(min(n1, n2)) * 100 / 14)
		if dist > limit {
			dist = limit
		}
	}

	if dist < 0 {
		return 0
	}

	return dist
}

func levenshtein(s1, s2 []byte) int {
	n1 := len(s1)
	n2 := len(s2)
	if n1 == 0 {
		return n2
	}
	if n2 == 0 {
		return n1
	}

	// Use two rows to save space
	row := make([]int, n2+1)
	for j := 0; j <= n2; j++ {
		row[j] = j
	}

	for i := 1; i <= n1; i++ {
		prev := i
		for j := 1; j <= n2; j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			val := min(row[j]+1, prev+1, row[j-1]+cost)
			row[j-1] = prev
			prev = val
		}
		row[n2] = prev
	}

	return row[n2]
}

// shrink compresses characters that repeat consecutively more than 3 times, which is part of ssdeep similarity algorithm
func shrink(s string, buf []byte) []byte {
	n := len(s)
	for i := range n {
		c := s[i]
		if i < 3 || c != s[i-1] || c != s[i-2] || c != s[i-3] {
			buf = append(buf, c)
		}
	}

	return buf
}

// findLongestCommonBytes finds the longest common substring in byte slices
// This function is used in the similarity calculation algorithm to find matching patterns between two hash byte slices.
func findLongestCommonBytes(a, b []byte, minLen int) (int, int, int) {
	na, nb := len(a), len(b)
	if na < minLen || nb < minLen {
		return 0, 0, 0
	}

	// Use uint8 DP table on stack since strings are short (max 64)
	// This fits well in L1 cache (4KB)
	var dp [65][65]uint8
	bestLen := 0
	bestIa, bestIb := 0, 0

	for i := 1; i <= na; i++ {
		for j := 1; j <= nb; j++ {
			if a[i-1] == b[j-1] {
				l := dp[i-1][j-1] + 1
				dp[i][j] = l
				if int(l) > bestLen {
					bestLen = int(l)
					bestIa = i - bestLen
					bestIb = j - bestLen
				}
			}
			// dp[i][j] is already 0 by default, so no need for else
		}
	}

	if bestLen >= minLen {
		return bestLen, bestIa, bestIb
	}
	return 0, 0, 0
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
