// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// DeviceDataSourceInstanceData device data source instance data
// swagger:model DeviceDataSourceInstanceData
type DeviceDataSourceInstanceData struct {

	// data source name
	// Read Only: true
	DataSourceName string `json:"dataSourceName,omitempty"`

	// next page params
	// Read Only: true
	NextPageParams string `json:"nextPageParams,omitempty"`

	// time
	// Read Only: true
	Time []int64 `json:"time"`

	// values
	// Read Only: true
	Values [][]interface{} `json:"values"`
}

// Validate validates this device data source instance data
func (m *DeviceDataSourceInstanceData) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeviceDataSourceInstanceData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeviceDataSourceInstanceData) UnmarshalBinary(b []byte) error {
	var res DeviceDataSourceInstanceData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
