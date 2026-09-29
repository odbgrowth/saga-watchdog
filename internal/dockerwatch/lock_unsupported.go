//go:build !linux && !darwin

package dockerwatch

import (
	"errors"
	"os"
)

func lockFile(*os.File) error {
	return errors.New("Docker observation requires a Linux or macOS Unix socket")
}
