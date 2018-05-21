package utilities

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/sethvargo/go-password/password"
)

var unacceptedPasswordCharacters = [...]string{
	"*",
	"`",
	"\"",
}

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
