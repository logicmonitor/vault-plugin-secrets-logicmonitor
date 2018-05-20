package utilities

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"reflect"
)

// CheckAllErrors is a helper function to deal with the number of possible places that an API call can fail.
func CheckAllErrors(restResponse interface{}, apiResponse *http.Response, err error) error {
	var restResponseMessage string
	var restResponseStatus int64

	// Get the underlying concrete type.
	t := reflect.ValueOf(restResponse)

	// Check it the interface is a pointer and get the underlying value.
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// Ensure that it is a struct, and get the necessary fields if they are available.
	if t.Kind() == reflect.Struct {
		field := t.FieldByName("Status")
		if field.IsValid() {
			restResponseStatus = field.Int()
		}
		field = t.FieldByName("Errmsg")
		if field.IsValid() {
			restResponseMessage = field.String()
		}
	}

	if restResponseStatus != http.StatusOK {
		return fmt.Errorf("[REST] [%d] %s", restResponseStatus, restResponseMessage)
	}

	if apiResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("[API] [%d] %s", apiResponse.StatusCode, restResponseMessage)
	}

	if err != nil {
		return fmt.Errorf("[ERROR] %v", err)
	}
	return nil
}

// len(encodeURL) == 64. This allows (x <= 265) x % 64 to have an even
// distribution.
const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// RandASCIIBytes creates and fills a slice of length n with characters from
// a-zA-Z0-9_-. It panics if there are any problems getting random bytes.
func RandASCIIBytes(n int) []byte {
	output := make([]byte, n)

	// We will take n bytes, one byte for each character of output.
	randomness := make([]byte, n)

	// read all random
	_, err := rand.Read(randomness)
	if err != nil {
		panic(err)
	}

	// fill output
	for pos := range output {
		// get random item
		random := uint8(randomness[pos])

		// random % 64
		randomPos := random % uint8(len(encodeURL))

		// put into output
		output[pos] = encodeURL[randomPos]
	}
	return output
}

// RandASCIIString creates and fills a string slice of length n with characters
// from a-zA-Z0-9_-. It panics if there are any problems getting random bytes.
func RandASCIIString(n int) string {
	b := RandASCIIBytes(n)
	return string(b[:n])
}
