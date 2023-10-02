package unsafeutil

import (
	"io"
	"unsafe"
)

const emptyStr = ""

// ReadAllStr reads byte array from a Reader and turns it directly into a
// string.
func ReadAllStr(r io.Reader) (string, error) {
	if r == nil {
		panic("Passed nil to ReadAllStr() as io.Reader")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return emptyStr, err
	}
	return AsString(b), nil
}

// AsString builds a string with the underlying array of a byte slice.
// Only use it when the original byte slice will not be mutated.
func AsString(b []byte) string {
	if b == nil || len(b) == 0 {
		return emptyStr
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// AsSlice retrieves the underlying byte slice for a string.
// Do not mutate the resulting byte slice.
func AsSlice(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
