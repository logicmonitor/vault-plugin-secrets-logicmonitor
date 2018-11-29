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

// SNMPAutoDiscoveryMethod s n m p auto discovery method
// swagger:model SNMPAutoDiscoveryMethod
type SNMPAutoDiscoveryMethod struct {

	// i l p
	ILP []*ILP `json:"ILP"`

	// o ID
	// Required: true
	OID *string `json:"OID"`

	// description o ID
	DescriptionOID string `json:"descriptionOID,omitempty"`

	// discovery type
	// Required: true
	DiscoveryType *string `json:"discoveryType"`

	// enable s n m p i l p
	EnableSNMPILP bool `json:"enableSNMPILP,omitempty"`

	// lookup o ID
	// Required: true
	LookupOID *string `json:"lookupOID"`
}

// Name gets the name of this subtype
func (m *SNMPAutoDiscoveryMethod) Name() string {
	return "ad_snmp"
}

// SetName sets the name of this subtype
func (m *SNMPAutoDiscoveryMethod) SetName(val string) {

}

// ILP gets the i l p of this subtype

// OID gets the o ID of this subtype

// DescriptionOID gets the description o ID of this subtype

// DiscoveryType gets the discovery type of this subtype

// EnableSNMPILP gets the enable s n m p i l p of this subtype

// LookupOID gets the lookup o ID of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *SNMPAutoDiscoveryMethod) UnmarshalJSON(raw []byte) error {
	var data struct {

		// i l p
		ILP []*ILP `json:"ILP"`

		// o ID
		// Required: true
		OID *string `json:"OID"`

		// description o ID
		DescriptionOID string `json:"descriptionOID,omitempty"`

		// discovery type
		// Required: true
		DiscoveryType *string `json:"discoveryType"`

		// enable s n m p i l p
		EnableSNMPILP bool `json:"enableSNMPILP,omitempty"`

		// lookup o ID
		// Required: true
		LookupOID *string `json:"lookupOID"`
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

	var result SNMPAutoDiscoveryMethod

	if base.Name != result.Name() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid name value: %q", base.Name)
	}

	result.ILP = data.ILP

	result.OID = data.OID

	result.DescriptionOID = data.DescriptionOID

	result.DiscoveryType = data.DiscoveryType

	result.EnableSNMPILP = data.EnableSNMPILP

	result.LookupOID = data.LookupOID

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m SNMPAutoDiscoveryMethod) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// i l p
		ILP []*ILP `json:"ILP"`

		// o ID
		// Required: true
		OID *string `json:"OID"`

		// description o ID
		DescriptionOID string `json:"descriptionOID,omitempty"`

		// discovery type
		// Required: true
		DiscoveryType *string `json:"discoveryType"`

		// enable s n m p i l p
		EnableSNMPILP bool `json:"enableSNMPILP,omitempty"`

		// lookup o ID
		// Required: true
		LookupOID *string `json:"lookupOID"`
	}{

		ILP: m.ILP,

		OID: m.OID,

		DescriptionOID: m.DescriptionOID,

		DiscoveryType: m.DiscoveryType,

		EnableSNMPILP: m.EnableSNMPILP,

		LookupOID: m.LookupOID,
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

// Validate validates this s n m p auto discovery method
func (m *SNMPAutoDiscoveryMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateILP(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDiscoveryType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLookupOID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SNMPAutoDiscoveryMethod) validateILP(formats strfmt.Registry) error {

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

func (m *SNMPAutoDiscoveryMethod) validateOID(formats strfmt.Registry) error {

	if err := validate.Required("OID", "body", m.OID); err != nil {
		return err
	}

	return nil
}

func (m *SNMPAutoDiscoveryMethod) validateDiscoveryType(formats strfmt.Registry) error {

	if err := validate.Required("discoveryType", "body", m.DiscoveryType); err != nil {
		return err
	}

	return nil
}

func (m *SNMPAutoDiscoveryMethod) validateLookupOID(formats strfmt.Registry) error {

	if err := validate.Required("lookupOID", "body", m.LookupOID); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SNMPAutoDiscoveryMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SNMPAutoDiscoveryMethod) UnmarshalBinary(b []byte) error {
	var res SNMPAutoDiscoveryMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
