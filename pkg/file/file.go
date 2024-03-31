package file

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

func OpenFileToWrite(path string, mode fs.FileMode) (*os.File, error) {
	path = filepath.FromSlash(path)
	if err := MakeParentDir(path); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return nil, errors.Wrapf(err, `open file "%s" to write`, path)
	}
	return file, nil
}

func OpenExistFileToWrite(path string, mode fs.FileMode) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, mode)
	if err != nil {
		return nil, errors.Wrapf(err, `open exist file "%s" to write`, path)
	}
	return file, nil
}

func MakeParentDir(path string) error {
	return MakeDir(filepath.Dir(path))
}

func MakeDir(path string) error {
	exist, err := IsDirExist(path)
	if err != nil {
		return err
	}
	if !exist {
		if err := os.MkdirAll(path, fs.FileMode(0755)); err != nil {
			return errors.Wrapf(err, `make all directories for "%s"`, path)
		}
	}
	return nil
}

func IsDirExist(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() {
		return true, fmt.Errorf(`"%s" is not a directory`, path)
	}
	return true, nil
}

func IsFileExist(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.IsDir() {
		return true, fmt.Errorf(`"%s" is not a file`, path)
	}
	return true, nil
}
