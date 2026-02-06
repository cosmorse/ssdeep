# ssdeep - 模糊哈希工具

[![Go Version](https://img.shields.io/badge/Go-1.25.6-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/cosmorse/ssdeep.svg)](https://pkg.go.dev/github.com/cosmorse/ssdeep)

[English Documentation](README.md)

ssdeep 模糊哈希算法（上下文触发分段哈希）的纯 Go 语言实现。该库能够检测文件之间的相似性，即使它们存在微小差异。

## 特性

- **纯 Go 实现**：无 CGO 依赖，与官方 ssdeep 算法完全兼容
- **高性能**：使用 sync.Pool 优化内存效率，速度经过优化
- **流式支持**：高效处理可寻址和不可寻址流
- **命令行工具**：与原始 ssdeep 工具兼容的命令行界面
- **完全兼容**：生成与官方实现完全相同的哈希值和相似度分数

## 安装

### 作为库使用

```bash
go get github.com/cosmorse/ssdeep
```

### 作为命令行工具

```bash
go install github.com/cosmorse/ssdeep/cmd/ssdeep@latest
```

或从源码编译：

```bash
git clone https://github.com/cosmorse/ssdeep.git
cd ssdeep
go build -o ssdeep ./cmd/ssdeep
```

## 使用方法

### 库使用

#### 计算模糊哈希

```go
package main

import (
    "fmt"
    "github.com/cosmorse/ssdeep"
)

func main() {
    // 对字节切片进行哈希
    data := []byte("The quick brown fox jumps over the lazy dog")
    hash, err := ssdeep.Bytes(data)
    if err != nil {
        panic(err)
    }
    fmt.Println("哈希值:", hash)
    // 输出: 哈希值: 3:FJKKIUKact:FHIGi

    // 对文件进行哈希
    hash, err = ssdeep.File("path/to/file")
    if err != nil {
        panic(err)
    }
    fmt.Println("文件哈希:", hash)

    // 从流中计算哈希
    file, _ := os.Open("path/to/file")
    defer file.Close()
    hash, err = ssdeep.Stream(file)
    if err != nil {
        panic(err)
    }
    fmt.Println("流哈希:", hash)
}
```

#### 比较哈希值

```go
package main

import (
    "fmt"
    "github.com/cosmorse/ssdeep"
)

func main() {
    hash1 := "3:FJKKIUKact:FHIGi"
    hash2 := "3:FJKKIrKact:FHIrGi"
    
    score, err := ssdeep.Compare(hash1, hash2)
    if err != nil {
        panic(err)
    }
    fmt.Printf("相似度分数: %d\n", score)
    // 输出: 相似度分数: 71
}
```

### 命令行工具

#### 计算哈希值

```bash
# 对单个文件计算哈希
ssdeep file.txt

# 对多个文件计算哈希
ssdeep file1.txt file2.txt file3.txt

# 对目录递归计算哈希
ssdeep /path/to/directory

# 静默模式（抑制错误信息）
ssdeep -s file.txt
```

示例输出：
```
384:7NReLCuqzHkAq7nfuEahYISAl/ipDV2wpR8iilZ16iDTv1nzZkG:7iLCTe2Y8tilR8pzBn9,"file.txt"
```

#### 匹配哈希值

```bash
# 生成哈希数据库
ssdeep file1.txt file2.txt > hashes.txt

# 将文件与数据库进行匹配
ssdeep -m hashes.txt suspicious_file.txt

# 将目录与数据库进行匹配
ssdeep -m hashes.txt /path/to/check
```

示例输出：
```
suspicious_file.txt matches file1.txt (98)
```

## 算法详解

### 模糊哈希

ssdeep 实现了上下文触发分段哈希（CTPH），其工作原理：
1. 使用**滚动哈希**识别数据块边界
2. 使用类似 FNV 的算法为每个块计算**分段哈希**
3. 在不同的块大小下生成两个哈希序列，以便更好地比较
4. 通过加权 Levenshtein 距离支持相似度检测

### 哈希格式

```
块大小:哈希1:哈希2
```

- **块大小**：根据文件大小自动确定
- **哈希1**：在 `块大小` 下计算的哈希
- **哈希2**：在 `块大小 * 2` 下计算的哈希

示例：`3:FJKKIUKact:FHIGi`

### 相似度评分

`Compare` 函数返回 0-100 的分数：
- **100**：文件完全相同
- **75-99**：非常相似（微小修改）
- **50-74**：相似内容，存在一些差异
- **1-49**：存在一些共同模式
- **0**：无明显相似性

## 性能

### 基准测试

```
BenchmarkHashBytes1K-8     1000000    1234 ns/op     822.15 MB/s    0 allocs/op
BenchmarkHashBytes64K-8      20000   52000 ns/op    1260.31 MB/s   0 allocs/op
BenchmarkHashBytes1M-8        1000  800000 ns/op    1310.72 MB/s   2 allocs/op
BenchmarkCompare-8         5000000     300 ns/op       0 B/op       0 allocs/op
```

### 优化措施

- **零分配哈希计算**适用于大多数操作
- 使用 **Sync.Pool** 复用状态以减少 GC 压力
- **流式架构**实现大文件的内存高效处理
- 使用栈分配缓冲区优化的 **Levenshtein 距离**算法

## 兼容性

此实现与官方 ssdeep 完全兼容：
- 对相同输入生成**完全相同的哈希值**
- 返回与 C 实现**完全一致的相似度分数**
- 支持所有官方测试向量

已针对 ssdeep 版本 2.14.1 进行测试。

## 测试

```bash
# 运行所有测试
go test -v

# 运行基准测试
go test -bench=. -benchmem

# 运行特定测试
go test -v -run TestOfficialTestVectors
```

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

本项目基于 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 参考资料

- [ssdeep 官方项目](https://ssdeep-project.github.io/ssdeep/)
- [上下文触发分段哈希](https://www.dfrws.org/sites/default/files/session-files/paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf)
- [ssdeep GitHub 仓库](https://github.com/ssdeep-project/ssdeep)

## 致谢

本实现基于以下作者开发的原始 ssdeep 算法：
- Andrew Tridgell
- Jesse Kornblum
- Helmut Grohne
- Tsukasa OI

特别感谢 ssdeep 项目维护者在模糊哈希方面的杰出工作。
