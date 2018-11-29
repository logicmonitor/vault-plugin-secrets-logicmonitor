// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// IPMICollectorAttribute IP m i collector attribute
// swagger:model IPMICollectorAttribute
type IPMICollectorAttribute struct {

	// ipmi sensor
	IPMISensor string `json:"ipmiSensor,omitempty"`
}

// Name gets the name of this subtype
func (m *IPMICollectorAttribute) Name() string {
	return "ipmi"
}

// SetName sets the name of this subtype
func (m *IPMICollectorAttribute) SetName(val string) {

}

// IPMISensor gets the ipmi sensor of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *IPMICollectorAttribute) UnmarshalJSON(raw []byte) error {
	var data struct {

		// ipmi sensor
		IPMISensor string `json:"ipmiSensor,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var base struct {
		/* Just the base type fields. Used for unmashalling polymorphic types.*/

		Name string `json:"name"`
	}
	buf = bytes.NewBuffer(raw)
	dec = json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&base); err != nil {
		return err
	}

	var result IPMICollectorAttribute

	if base.Name != result.Name() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid name value: %q", base.Name)
	}

	result.IPMISensor = data.IPMISensor

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m IPMICollectorAttribute) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// ipmi sensor
		IPMISensor string `json:"ipmiSensor,omitempty"`
	}{

		IPMISensor: m.IPMISensor,
	},
	)
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		Name string `json:"name"`
	}{

		Name: m.Name(),
	},
	)
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this IP m i collector attribute
func (m *IPMICollectorAttribute) Validate(formats strfmt.Registry) error {
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *IPMICollectorAttribute) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *IPMICollectorAttribute) UnmarshalBinary(b []byte) error {
	var res IPMICollectorAttribute
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
