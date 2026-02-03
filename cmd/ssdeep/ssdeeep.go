package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gitee.com/cosmorse/ssdeep"
	"github.com/spf13/cobra"
)

var (
	silent    bool
	matchFile string
)

var rootCmd = &cobra.Command{
	Use:                   "ssdeep [options] files",
	Short:                 "ssdeep fuzzy hashing tool",
	Long:                  "ssdeep is a tool for computing and matching fuzzy hashes (Context Triggered Piecewise Hashing).",
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		if matchFile != "" {
			runMatch(args)
			return
		}

		for _, arg := range args {
			processPath(arg)
		}
	},
}

func runMatch(args []string) {
	hashes, err := loadHashes(matchFile)
	if err != nil {
		if !silent {
			fmt.Fprintf(os.Stderr, "ssdeep: %v\n", err)
		}
		os.Exit(1)
	}

	for _, arg := range args {
		matchPath(arg, hashes)
	}
}

type hashInfo struct {
	hash string
	path string
}

func loadHashes(path string) ([]hashInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []hashInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			hash := parts[0]
			targetPath := strings.Trim(parts[1], "\"")
			hashes = append(hashes, hashInfo{hash: hash, path: targetPath})
		}
	}
	return hashes, scanner.Err()
}

func matchPath(path string, hashes []hashInfo) {
	info, err := os.Stat(path)
	if err != nil {
		if !silent {
			fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", path, err)
		}
		return
	}

	if info.IsDir() {
		filepath.Walk(path, func(p string, i os.FileInfo, e error) error {
			if e != nil {
				if !silent {
					fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", p, e)
				}
				return nil
			}
			if !i.IsDir() {
				matchFileAgainstHashes(p, hashes)
			}
			return nil
		})
	} else {
		matchFileAgainstHashes(path, hashes)
	}
}

func matchFileAgainstHashes(path string, hashes []hashInfo) {
	hash, err := ssdeep.File(path)
	if err != nil {
		if !silent {
			fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", path, err)
		}
		return
	}

	for _, h := range hashes {
		score, err := ssdeep.Compare(hash, h.hash)
		if err == nil && score > 0 {
			fmt.Printf("%s matches %s (%d)\n", path, h.path, score)
		}
	}
}

func processPath(path string) {
	info, err := os.Stat(path)
	if err != nil {
		if !silent {
			fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", path, err)
		}
		return
	}

	if info.IsDir() {
		filepath.Walk(path, func(p string, i os.FileInfo, e error) error {
			if e != nil {
				if !silent {
					fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", p, e)
				}
				return nil
			}
			if !i.IsDir() {
				hashAndPrint(p)
			}
			return nil
		})
	} else {
		hashAndPrint(path)
	}
}

func hashAndPrint(path string) {
	hash, err := ssdeep.File(path)
	if err != nil {
		if !silent {
			fmt.Fprintf(os.Stderr, "ssdeep: %s: %v\n", path, err)
		}
		return
	}
	fmt.Printf("%s,\"%s\"\n", hash, path)
}

func main() {
	rootCmd.Flags().BoolVarP(&silent, "silent", "s", false, "silent mode - suppresses error messages")
	rootCmd.Flags().StringVarP(&matchFile, "match", "m", "", "match files against hashes in file")

	rootCmd.SetUsageTemplate(`Usage: {{if .Runnable}}{{.UseLine}}{{end}} {{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Options:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Options:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
