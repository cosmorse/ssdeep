// package ssdeep 实现了 ssdeep (模糊哈希) 算法。
// 该算法用于计算文件的相似度，即使文件内容有微小差异也能生成相似的哈希值。
package ssdeep

import (
	"fmt"
	"io"
	"strings"
)

const (
	// minBlockSize 是最小的分块大小
	minBlockSize = 3
	// windowSize 是 rolling hash 使用的滑动窗口大小
	windowSize = 7
	// maxResultLen 是生成哈希部分的最大长度（通常为 64 字符）
	maxResultLen = 64
	// base64Chars 是用于哈希输出的字符集
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// hashInit 是 piecewise hash 的初始值（与官方兼容的值）
	hashInit = 0x01234567
)

// ssdeepState 存储哈希计算的中间状态
type ssdeepState struct {
	blockSize uint32 // 当前使用的分块大小

	// Rolling hash 状态
	h1, h2, h3 uint32           // 滚动哈希的三个组成部分
	window     [windowSize]byte // 滑动窗口缓冲
	n          uint32           // 已处理的字节计数，用于窗口索引

	// Piecewise hash 状态
	p1 uint32 // 用于 blockSize 的分段哈希值
	p2 uint32 // 用于 blockSize * 2 的分段哈希值

	// 结果缓冲
	res1 []byte // 对应 blockSize 的哈希字符串
	res2 []byte // 对应 blockSize * 2 的哈希字符串
}

// newSSDeepState 初始化一个新的 ssdeepState
func newSSDeepState(blockSize uint32) *ssdeepState {
	return &ssdeepState{
		blockSize: blockSize,
		p1:        hashInit,
		p2:        hashInit,
		res1:      make([]byte, 0, maxResultLen+1),
		res2:      make([]byte, 0, maxResultLen+1),
	}
}

// Write 处理输入的字节流并更新哈希状态。
// 它同时维护滚动哈希（用于确定分块边界）和分段哈希（用于计算块内容摘要）。
func (s *ssdeepState) Write(p []byte) (n int, err error) {
	bs1 := s.blockSize
	bs2 := bs1 * 2
	h1, h2, h3 := s.h1, s.h2, s.h3
	p1, p2 := s.p1, s.p2
	n_idx := s.n

	for _, c := range p {
		u_c := uint32(c)

		// 恢复原实现的滚动哈希实现（与原库行为一致）
		// 该实现在实践中会产生更多边界触发，匹配官方行为
		h2 -= h1
		h2 += windowSize * u_c

		h1 += u_c
		h1 -= uint32(s.window[n_idx%windowSize])

		s.window[n_idx%windowSize] = c
		n_idx++

		h3 <<= 5
		h3 ^= u_c

		// 分段哈希更新（mul then xor）以匹配官方实现：p = (p * FNV_PRIME) ^ c
		p1 = (p1 * 16777619) ^ u_c
		p2 = (p2 * 16777619) ^ u_c

		h := h1 + h2 + h3

		// 检查是否到达第一个分块边界 (blockSize)
		if h%bs1 == (bs1 - 1) {
			if len(s.res1) < maxResultLen {
				s.res1 = append(s.res1, base64Chars[p1%64])
			}
			p1 = hashInit // 重置分段哈希以便处理下一块
		}

		// 检查是否到达第二个分块边界 (blockSize * 2)
		if h%bs2 == (bs2 - 1) {
			if len(s.res2) < maxResultLen {
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

// Compare 计算两个 ssdeep 哈希值之间的相似度得分（0 到 100）。
// 得分为 100 表示完全相同，0 表示没有显著相似性。
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

// score 计算两个哈希分段字符串的相似度，采用与官方兼容的算法：
// 先对字符串做 shrink 处理，然后反复寻找长度 >= 3 的最长公共子串并移除，
// 统计匹配字符数，最后按官方公式计算得分。
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

// shrink 压缩字符串中连续重复超过 3 次的字符，这是 ssdeep 相似度算法的一部分
func shrink(s string) string {
	if len(s) <= 3 {
		return s
	}
	res := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		// 如果当前字符与前三个字符都相同，则跳过
		if i < 3 || s[i] != s[i-1] || s[i] != s[i-2] || s[i] != s[i-3] {
			res = append(res, s[i])
		}
	}
	return string(res)
}

// findLongestCommonSubstring 在 a, b 中寻找最长公共子串（长度至少为 minLen），
// 返回 (长度, 在 a 中的位置, 在 b 中的位置)。
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

// Sum 返回最终生成的 ssdeep 哈希字符串，格式为 "blockSize:hash1:hash2"
func (s *ssdeepState) Sum() string {
	// 即使没有到达边界，也要处理剩余的数据
	r1 := s.res1
	if s.p1 != hashInit && len(r1) < maxResultLen {
		r1 = append(r1, base64Chars[s.p1%64])
	}
	r2 := s.res2
	if s.p2 != hashInit && len(r2) < maxResultLen {
		r2 = append(r2, base64Chars[s.p2%64])
	}

	return fmt.Sprintf("%d:%s:%s", s.blockSize, string(r1), string(r2))
}

// HashBytes 计算给定字节数组的 ssdeep 模糊哈希值。
func HashBytes(data []byte) (string, error) {
	if len(data) == 0 {
		return fmt.Sprintf("%d::", minBlockSize), nil
	}
	// 估算最合适的块大小
	blockSize := estimateBlockSize(int64(len(data)))
	s := newSSDeepState(blockSize)
	_, _ = s.Write(data)
	return s.Sum(), nil
}

// HashReader 从 io.Reader 计算 ssdeep 模糊哈希值。
// 对于实现了 io.ReadSeeker 的对象（如文件），它会预先获取大小以优化内存。
func HashReader(r io.Reader) (string, error) {
	if rs, ok := r.(io.ReadSeeker); ok {
		size, err := rs.Seek(0, io.SeekEnd)
		if err != nil {
			return "", err
		}
		_, err = rs.Seek(0, io.SeekStart)
		if err != nil {
			return "", err
		}
		blockSize := estimateBlockSize(size)
		s := newSSDeepState(blockSize)
		_, err = io.Copy(s, r)
		if err != nil {
			return "", err
		}
		return s.Sum(), nil
	}

	// 对于普通的 Reader，需要读取全部内容以确定大小并估算块大小。
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return HashBytes(data)
}

// estimateBlockSize 根据数据总大小估算初始块大小，旨在让生成的哈希长度接近 64 字符。
func estimateBlockSize(size int64) uint32 {
	blockSize := uint32(minBlockSize)
	for uint64(blockSize)*maxResultLen < uint64(size) {
		blockSize *= 2
	}
	return blockSize
}
