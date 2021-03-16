package userside

import (
	"bytes"
	gp "github.com/number571/gopeer"
)

func RaiseEntropy(info, salt []byte, bits int) []byte {
	lim := uint64(1 << bits)
	for i := uint64(0); i < lim; i++ {
		info = gp.HashSum(bytes.Join(
			[][]byte{
				info,
				salt,
			},
			[]byte{},
		))
	}
	return info
}
