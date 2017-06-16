package main

import (
	"archive/tar"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"

	"compress/gzip"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	usage = `Usage:
	backup [--help] <build|restore> [--help] [OPTIONS]`

	help = usage + `

Used to build and restore a backup of a user directory according to a list file
specifying files to be included and excluded.

To see more about each command, use 'backup <command> --help'.

Commands:
	backup     builds a backup
	restore    restores from a backup file`
)

type exitError struct {
	msg  string
	code int
}

func (e exitError) Error() string {
	return e.msg
}

type homeError struct {
	who    string
	reason string
}

func (e homeError) Error() string {
	if e.who == "" {
		return "Unable to find current user's home directory: " + e.reason
	}
	return fmt.Sprintf("Unable to find home directory of user %s: %s", e.who, e.reason)
}

func main() {
	var exitCode int = program()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func program() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		return 1
	}

	var err error
	switch os.Args[1] {
	case "build":
		err = build(os.Args[2:])
	case "restore":
		err = restore(os.Args[2:])
	case "--help", "-h":
		fmt.Println(help)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized command '%s'\n", os.Args[1])
		return 1
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		if exit, ok := err.(exitError); ok {
			return exit.code
		}
		return 2
	}
	return 0
}

func build(args []string) error {
	listPaths := []string{}
	outPaths := []string{}
	for i := 0; i < len(args); i += 2 {
		switch args[i] {
		case "--help", "-h":
			fmt.Println(`Usage:
	backup build [--help] [-l LIST] [-o OUTPUT]

The build command backs up a list of files as determined by the provided lists
and saves them in an AES encrypted tarball.The list files operate in stages,
indicated by either [include] or [exclude] markers.  After each marker, backup
looks for a newline-delimited list of glob patterns to match agains files.  You
can add an unlimited number of stages of [include] and [exclude] that will be
evaluated in order.  If the first marker is an include, it is assumed everything
else is excluded by default, and if the first stage is an exclude, it is assumed
everything in your user directory is included by default.

You can set multiple list files and output paths by using their options twice,
as in 'backup -l list1 -l list2 -o backup1 -o backup2'.  In this case, the list
files will be loaded in the order that they're listed.

Options:
	-h, --help      this help message
	-l, --list      file that contains what's to be excluded and included in the backup, defaults to ./backup.list
	-o, --output    where to store the backup file, by default the output is printed to standard out`)
			return nil

		case "-l", "--list":
			s := tryGetArg(args, i+1)
			if s == "" {
				return exitError{
					msg:  fmt.Sprintf("Expected argument after '%s'", args[i]),
					code: 1,
				}
			}
			listPaths = append(listPaths, s)
		case "-o", "--output":
			s := tryGetArg(args, i+1)
			if s == "" {
				return exitError{
					msg:  fmt.Sprintf("Expected argument after '%s'", args[i]),
					code: 1,
				}
			}
			outPaths = append(outPaths, s)
		}
	}

	if len(listPaths) == 0 {
		listPaths = append(listPaths, "backup.list") // the default list file
	}
	return runBuild(listPaths, outPaths)
}

func runBuild(listPaths []string, outPaths []string) error {
	stages := []buildStage{}
	for _, listPath := range listPaths {
		file, err := os.Open(listPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open list file '%s': %s\n", listPath, err.Error())
			continue
		}

		stages, err = loadStages(file, stages)
		if err != nil {
			return err
		}
		file.Close()
	}

	var output io.Writer
	if len(outPaths) == 0 {
		output = os.Stdout
	} else {
		var opened []io.Writer
		for _, outPath := range outPaths {
			file, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return err
			}
			defer file.Close()
			opened = append(opened, file)
		}
		if len(opened) == 1 {
			output = opened[0]
		} else {
			output = io.MultiWriter(opened...)
		}
	}

	err := goHome()
	if err != nil {
		return fmt.Errorf("Unable to chdir into home directory: %s", err.Error())
	}

	fileList, err := compileStages(stages)
	if err != nil {
		return err
	}

	// aesStream, err := setupCryptoStream(output)
	// if err != nil {
	// 	return err
	// }
	// defer aesStream.Close()

	// archiver := tar.NewWriter(aesStream)
	// defer archiver.Close()

	compressor := gzip.NewWriter(output)
	defer compressor.Close()
	archiver := tar.NewWriter(compressor)
	defer archiver.Close()

	for _, path := range fileList {
		err = archiveFile(archiver, path)
		if err != nil {
			return err
		}
	}
	return nil
}

// loadStages operates similarly to the append function
func loadStages(file *os.File, stages []buildStage) ([]buildStage, error) {
	var stage *buildStage
	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "[include]":
			stages = append(stages, buildStage{
				include: true,
				source:  file.Name(),
			})
			stage = &stages[len(stages)-1]
		case "[exclude]":
			stages = append(stages, buildStage{
				include: false,
				source:  file.Name(),
			})
			stage = &stages[len(stages)-1]
		case "": // don't add empty lines
		default:
			if stage == nil {
				// if we haven't reached an [include] or [exclude] header
				continue
			}

			stage.rules = append(stage.rules, buildRule{glob: line, line: i})
		}
	}
	return stages, nil
}

// compileStages used the rules set out in stages to build a list of files to
// back up
func compileStages(stages []buildStage) ([]string, error) {
	if len(stages) == 0 {
		return nil, nil
	}

	// first, build a list of all the exclusion rules, in order
	exclusions := []string{}
	for _, stage := range stages {
		if !stage.include { // !include = exclude
			for _, rule := range stage.rules {
				exclusions = append(exclusions, rule.glob)
			}
		}
	}

	list := []string{}
	for _, stage := range stages {
		if stage.include {
			for _, rule := range stage.rules {
				var glob []string
				glob, _ = filepath.Glob(rule.glob)
				// now check the files we've found against all future exclusions
				for _, file := range glob {
					filepath.Walk(file, func(wpath string, info os.FileInfo, err error) error {
						excluded := false
						var full, base bool
						for _, excl := range exclusions {
							full, _ = filepath.Match(excl, wpath)
							base, _ = filepath.Match(excl, path.Base(wpath))
							if full || base {
								excluded = true
								break
							}
						}
						if skipFileType(info) {
							return nil
						} else if info.IsDir() {
							if excluded {
								// don't recurse into excluded directories
								return filepath.SkipDir
							}
						} else if !excluded {
							list = append(list, wpath)
						}
						return nil
					})
				}
			}
		} else {
			// we no longer need to check against the rules listed in this stage
			// because they're listed before any more inclusions we encounter
			exclusions = exclusions[len(stage.rules):]
		}
	}

	return list, nil
}

// skipFileType checks to see if a file can be skipped based on its type stored
// in the mode.  Types that aren't skipped are: regular, directory, symlink, and
// hardlinks.  Temporary files are skipped.  A return value of true indicates
// the file should be skipped, false indicates it should be kept.
func skipFileType(info os.FileInfo) bool {
	if info.Mode()&os.ModeTemporary != 0 {
		return true
	}
	switch info.Mode() & os.ModeType {
	case os.ModeDir, os.ModeSymlink:
		return false
	}
	if info.Mode().IsRegular() {
		return false
	}
	return true
}

type ioCombo struct {
	r io.Reader
	w io.Writer
}

func (io ioCombo) Read(data []byte) (int, error) {
	return io.r.Read(data)
}

func (io ioCombo) Write(data []byte) (int, error) {
	return io.w.Write(data)
}

type managedWriter struct {
	w        io.Writer
	password []byte
}

func (w managedWriter) Write(data []byte) (int, error) {
	return w.w.Write(data)
}

func (w managedWriter) Close() error {
	for i := range w.password {
		w.password[i] = 0
	}
	return nil
}

func setupCryptoStream(output io.Writer) (io.WriteCloser, error) {
	var term *terminal.Terminal = terminal.NewTerminal(ioCombo{r: os.Stdin, w: os.Stdout}, "Password: ")
	password, err := term.ReadPassword("Password: ")
	if err != nil {
		return nil, err
	}

	// add padding/stip end to make password 32 bytes long to enable AES-256
	if len(password) < 32 {
		password += string(make([]byte, 32-len(password)))
	} else if len(password) > 32 {
		password = password[:32]
	}

	var block cipher.Block
	block, _ = aes.NewCipher([]byte(password))

	var iv [aes.BlockSize]byte
	_, err = rand.Read(iv[:])
	if err != nil {
		return nil, err
	}

	// first, save the IV in the first aes.BlockSize (16) bytes of the output
	_, err = output.Write(iv[:])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, iv[:])
	return managedWriter{
		password: []byte(password),
		w:        &cipher.StreamWriter{S: stream, W: output},
	}, nil
}

func archiveFile(archiver *tar.Writer, path string) error {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open '%s': %s\n", path, err.Error())
		return nil
	}
	defer file.Close()

	header := buildTarHeader(path)
	if header == nil {
		return nil
	}
	err = archiver.WriteHeader(header)
	if err != nil {
		return nil
	}
	if header.Typeflag == tar.TypeSymlink {
		// don't write anything for symlinks, the target is contained in the header
		return nil
	}
	_, err = io.Copy(archiver, file)
	if err != nil {
		return fmt.Errorf("Error archiving '%s': %s", path, err.Error())
	}
	return nil
}

// goHome chdirs into our home directory
func goHome() error {
	me, err := user.Current()
	if err != nil {
		return err
	}
	return os.Chdir(me.HomeDir)
}

// stage represents a single [include/exclude] directive
type buildStage struct {
	// if false, exclude
	include bool
	// source is the name of the file from which this stage originates
	source string
	rules  []buildRule
}

type buildRule struct {
	glob string
	line int
}

func restore(args []string) error {
	var backupPath string
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			fmt.Println(`Usage:
	backup restore [--help] <backup_file> 

Restores the files provided in the given backup archive.`)
			return nil

		default:
			if backupPath != "" {
				return exitError{
					msg:  "Can only restore from one backup at a time",
					code: 1,
				}
			}
			backupPath = arg
		}
	}

	return nil
}

func tryGetArg(args []string, index int) string {
	if index < 0 || index > len(args) {
		return ""
	}
	return args[index]
}
