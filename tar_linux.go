package main

import (
	"archive/tar"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -std=c99
#define _POSIX_SOURCE
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct names_t {
	char* username;
	char* groupname;
} names_t;

names_t convertIds(uint32_t uid, uint32_t gid) {
	names_t names;
	names.username = NULL;
	names.groupname = NULL;

	struct passwd pwd;
	struct passwd *user_result;
	size_t buf_len = 100;
	char* ubuf = malloc(buf_len);
	getpwuid_r((uid_t)uid, &pwd, ubuf, buf_len, &user_result);

	if (user_result == NULL) {
		free(ubuf);
	} else {
		names.username = pwd.pw_name;
	}

	struct group grp;
	struct group *grp_result;
	char* gbuf = malloc(buf_len);
	getgrgid_r((gid_t)gid, &grp, gbuf, buf_len, &grp_result);

	if (grp_result == NULL) {
		free(gbuf);
	} else {
		names.groupname = grp.gr_name;
	}

	return names;
}
*/
import "C"

// buildTarHeader runs Lstat on the provided path and returns a tar header with
// all the information converted over.  Returns nil on error.
//
// TODO: include device major and minor numbers
func buildTarHeader(path string) *tar.Header {
	var info unix.Stat_t
	err := unix.Lstat(path, &info)
	if err != nil {
		return nil
	}

	var names C.names_t = C.convertIds(C.uint32_t(info.Uid), C.uint32_t(info.Gid))
	defer C.free(unsafe.Pointer(names.username))
	defer C.free(unsafe.Pointer(names.groupname))

	username := C.GoString(names.username)
	groupname := C.GoString(names.groupname)

	linkname, _ := os.Readlink(path)

	var tarType byte
	switch info.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		tarType = tar.TypeDir
	case unix.S_IFLNK:
		tarType = tar.TypeSymlink
	case unix.S_IFBLK:
		tarType = tar.TypeBlock
	case unix.S_IFCHR:
		tarType = tar.TypeChar
	case unix.S_IFIFO:
		tarType = tar.TypeFifo
	default:
		tarType = tar.TypeReg
	}

	return &tar.Header{
		Name:       path,
		Mode:       int64(info.Mode),
		Uid:        int(info.Uid),
		Gid:        int(info.Gid),
		Size:       info.Size,
		Uname:      username,
		Gname:      groupname,
		ModTime:    time.Unix(info.Mtim.Unix()),
		Typeflag:   tarType,
		Linkname:   linkname,
		AccessTime: time.Unix(info.Atim.Unix()),
		ChangeTime: time.Unix(info.Ctim.Unix()),
	}
}
