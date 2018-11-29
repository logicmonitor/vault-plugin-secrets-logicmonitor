// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// GraphPlotLine graph plot line
// swagger:model GraphPlotLine
type GraphPlotLine struct {

	// avg
	// Read Only: true
	Avg float64 `json:"avg,omitempty"`

	// color
	// Read Only: true
	Color string `json:"color,omitempty"`

	// color name
	// Read Only: true
	ColorName string `json:"colorName,omitempty"`

	// data
	// Read Only: true
	Data []interface{} `json:"data"`

	// decimal
	// Read Only: true
	Decimal int32 `json:"decimal,omitempty"`

	// description
	// Read Only: true
	Description string `json:"description,omitempty"`

	// label
	// Read Only: true
	Label string `json:"label,omitempty"`

	// legend
	// Read Only: true
	Legend string `json:"legend,omitempty"`

	// max
	// Read Only: true
	Max float64 `json:"max,omitempty"`

	// min
	// Read Only: true
	Min float64 `json:"min,omitempty"`

	// std
	// Read Only: true
	Std float64 `json:"std,omitempty"`

	// type
	// Read Only: true
	Type string `json:"type,omitempty"`

	// use y max
	// Read Only: true
	UseYMax *bool `json:"useYMax,omitempty"`

	// visible
	// Read Only: true
	Visible *bool `json:"visible,omitempty"`
}

// Validate validates this graph plot line
func (m *GraphPlotLine) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *GraphPlotLine) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GraphPlotLine) UnmarshalBinary(b []byte) error {
	var res GraphPlotLine
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}