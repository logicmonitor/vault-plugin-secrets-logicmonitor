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
	"github.com/go-openapi/validate"
)

// WMIAutoDiscoveryMethod w m i auto discovery method
// swagger:model WMIAutoDiscoveryMethod
type WMIAutoDiscoveryMethod struct {

	// i l p
	ILP []*ILP `json:"ILP"`

	// enable linked class i l p
	EnableLinkedClassILP bool `json:"enableLinkedClassILP,omitempty"`

	// enable wmi class i l p
	EnableWmiClassILP bool `json:"enableWmiClassILP,omitempty"`

	// linked classes
	LinkedClasses []*LinkedWmiClass `json:"linkedClasses"`

	// namespace
	// Required: true
	Namespace *string `json:"namespace"`

	// property
	// Required: true
	Property *string `json:"property"`

	// wmi class
	// Required: true
	WmiClass *string `json:"wmiClass"`
}

// Name gets the name of this subtype
func (m *WMIAutoDiscoveryMethod) Name() string {
	return "ad_wmi"
}

// SetName sets the name of this subtype
func (m *WMIAutoDiscoveryMethod) SetName(val string) {

}

// ILP gets the i l p of this subtype

// EnableLinkedClassILP gets the enable linked class i l p of this subtype

// EnableWmiClassILP gets the enable wmi class i l p of this subtype

// LinkedClasses gets the linked classes of this subtype

// Namespace gets the namespace of this subtype

// Property gets the property of this subtype

// WmiClass gets the wmi class of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *WMIAutoDiscoveryMethod) UnmarshalJSON(raw []byte) error {
	var data struct {

		// i l p
		ILP []*ILP `json:"ILP"`

		// enable linked class i l p
		EnableLinkedClassILP bool `json:"enableLinkedClassILP,omitempty"`

		// enable wmi class i l p
		EnableWmiClassILP bool `json:"enableWmiClassILP,omitempty"`

		// linked classes
		LinkedClasses []*LinkedWmiClass `json:"linkedClasses"`

		// namespace
		// Required: true
		Namespace *string `json:"namespace"`

		// property
		// Required: true
		Property *string `json:"property"`

		// wmi class
		// Required: true
		WmiClass *string `json:"wmiClass"`
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

	var result WMIAutoDiscoveryMethod

	if base.Name != result.Name() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid name value: %q", base.Name)
	}

	result.ILP = data.ILP

	result.EnableLinkedClassILP = data.EnableLinkedClassILP

	result.EnableWmiClassILP = data.EnableWmiClassILP

	result.LinkedClasses = data.LinkedClasses

	result.Namespace = data.Namespace

	result.Property = data.Property

	result.WmiClass = data.WmiClass

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m WMIAutoDiscoveryMethod) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// i l p
		ILP []*ILP `json:"ILP"`

		// enable linked class i l p
		EnableLinkedClassILP bool `json:"enableLinkedClassILP,omitempty"`

		// enable wmi class i l p
		EnableWmiClassILP bool `json:"enableWmiClassILP,omitempty"`

		// linked classes
		LinkedClasses []*LinkedWmiClass `json:"linkedClasses"`

		// namespace
		// Required: true
		Namespace *string `json:"namespace"`

		// property
		// Required: true
		Property *string `json:"property"`

		// wmi class
		// Required: true
		WmiClass *string `json:"wmiClass"`
	}{

		ILP: m.ILP,

		EnableLinkedClassILP: m.EnableLinkedClassILP,

		EnableWmiClassILP: m.EnableWmiClassILP,

		LinkedClasses: m.LinkedClasses,

		Namespace: m.Namespace,

		Property: m.Property,

		WmiClass: m.WmiClass,
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

// Validate validates this w m i auto discovery method
func (m *WMIAutoDiscoveryMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateILP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLinkedClasses(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNamespace(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProperty(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWmiClass(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WMIAutoDiscoveryMethod) validateILP(formats strfmt.Registry) error {

	if swag.IsZero(m.ILP) { // not required
		return nil
	}

	for i := 0; i < len(m.ILP); i++ {
		if swag.IsZero(m.ILP[i]) { // not required
			continue
		}

		if m.ILP[i] != nil {
			if err := m.ILP[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ILP" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *WMIAutoDiscoveryMethod) validateLinkedClasses(formats strfmt.Registry) error {

	if swag.IsZero(m.LinkedClasses) { // not required
		return nil
	}

	for i := 0; i < len(m.LinkedClasses); i++ {
		if swag.IsZero(m.LinkedClasses[i]) { // not required
			continue
		}

		if m.LinkedClasses[i] != nil {
			if err := m.LinkedClasses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("linkedClasses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *WMIAutoDiscoveryMethod) validateNamespace(formats strfmt.Registry) error {

	if err := validate.Required("namespace", "body", m.Namespace); err != nil {
		return err
	}

	return nil
}

func (m *WMIAutoDiscoveryMethod) validateProperty(formats strfmt.Registry) error {

	if err := validate.Required("property", "body", m.Property); err != nil {
		return err
	}

	return nil
}

func (m *WMIAutoDiscoveryMethod) validateWmiClass(formats strfmt.Registry) error {

	if err := validate.Required("wmiClass", "body", m.WmiClass); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *WMIAutoDiscoveryMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WMIAutoDiscoveryMethod) UnmarshalBinary(b []byte) error {
	var res WMIAutoDiscoveryMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
