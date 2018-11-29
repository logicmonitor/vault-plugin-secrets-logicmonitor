// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"encoding/json"
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// ESXCollectorAttribute e s x collector attribute
// swagger:model ESXCollectorAttribute
type ESXCollectorAttribute struct {

	// counters
	Counters []*DataSourceAttribute `json:"counters"`

	// entity
	Entity string `json:"entity,omitempty"`
}

// Name gets the name of this subtype
func (m *ESXCollectorAttribute) Name() string {
	return "esx"
}

// SetName sets the name of this subtype
func (m *ESXCollectorAttribute) SetName(val string) {

}

// Counters gets the counters of this subtype

// Entity gets the entity of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *ESXCollectorAttribute) UnmarshalJSON(raw []byte) error {
	var data struct {

		// counters
		Counters []*DataSourceAttribute `json:"counters"`

		// entity
		Entity string `json:"entity,omitempty"`
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

	var result ESXCollectorAttribute

	if base.Name != result.Name() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid name value: %q", base.Name)
	}

	result.Counters = data.Counters

	result.Entity = data.Entity

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m ESXCollectorAttribute) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// counters
		Counters []*DataSourceAttribute `json:"counters"`

		// entity
		Entity string `json:"entity,omitempty"`
	}{

		Counters: m.Counters,

		Entity: m.Entity,
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

// Validate validates this e s x collector attribute
func (m *ESXCollectorAttribute) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCounters(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ESXCollectorAttribute) validateCounters(formats strfmt.Registry) error {

	if swag.IsZero(m.Counters) { // not required
		return nil
	}

	for i := 0; i < len(m.Counters); i++ {
		if swag.IsZero(m.Counters[i]) { // not required
			continue
		}

		if m.Counters[i] != nil {
			if err := m.Counters[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("counters" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ESXCollectorAttribute) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ESXCollectorAttribute) UnmarshalBinary(b []byte) error {
	var res ESXCollectorAttribute
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
