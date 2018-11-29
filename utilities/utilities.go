package utilities

import (
	"strings"

	"github.com/sethvargo/go-password/password"
)

var unacceptedPasswordCharacters = [...]string{
	"*",
	"`",
	"\"",
}

// LiteralInt32Pointer returns a pointer containing the literal value
func LiteralInt32Pointer(x int32) *int32 {
	return &x
}

// LiteralBoolPointer returns a pointer containing the literal value
func LiteralBoolPointer(x bool) *bool {
	return &x
}

// GeneratePassword random password generator
func GeneratePassword() (string, error) {
	pw, err := password.Generate(20, 5, 5, false, true)
	if err != nil {
		return "", err
	}
	for _, c := range unacceptedPasswordCharacters {
		pw = strings.Replace(pw, c, "", -1)
	}
	return pw, nil
}
