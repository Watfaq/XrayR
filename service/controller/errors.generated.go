package controller

import "github.com/xtls/xray-core/common/errors"

func newError(values ...any) *errors.Error {
	return errors.New(values...)
}
