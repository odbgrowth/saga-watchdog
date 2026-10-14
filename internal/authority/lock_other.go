//go:build !linux && !darwin

package authority

import "errors"

func lockPath(string) (func(), error) {
	return nil, errors.New("persistent authority state requires Linux or macOS")
}
