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

// GaugeWidget gauge widget
// swagger:model GaugeWidget
type GaugeWidget struct {
	dashboardIdField *int32

	descriptionField string

	idField int32

	intervalField int32

	lastUpdatedByField string

	lastUpdatedOnField int64

	nameField *string

	themeField string

	timescaleField string

	userPermissionField string

	// The threshold of Gauge color changes
	ColorThresholds []*ColorThreshold `json:"colorThresholds"`

	// The datapoint whose value is displayed in the gauge widget
	// Required: true
	DataPoint *GaugeDataPoint `json:"dataPoint"`

	// Display as "Raw Value" or "Percent"
	DisplayType int32 `json:"displayType,omitempty"`

	// The unit for the raw value
	DisplayUnit string `json:"displayUnit,omitempty"`

	// The legend for the widget, displayed underneath the gauge
	Legend string `json:"legend,omitempty"`

	// The maximum value of the gauge widget, displayed on the right side of the gauge
	MaxValue float64 `json:"maxValue,omitempty"`

	// The minimum value of the gauge widget, displayed on the left side of the gauge
	MinValue float64 `json:"minValue,omitempty"`

	// The time range over which the peak value is determined
	PeakTimeRange string `json:"peakTimeRange,omitempty"`

	// Whether or not the peak value is displayed on the gauge widget
	ShowPeak bool `json:"showPeak,omitempty"`
}

// DashboardID gets the dashboard Id of this subtype
func (m *GaugeWidget) DashboardID() *int32 {
	return m.dashboardIdField
}

// SetDashboardID sets the dashboard Id of this subtype
func (m *GaugeWidget) SetDashboardID(val *int32) {
	m.dashboardIdField = val
}

// Description gets the description of this subtype
func (m *GaugeWidget) Description() string {
	return m.descriptionField
}

// SetDescription sets the description of this subtype
func (m *GaugeWidget) SetDescription(val string) {
	m.descriptionField = val
}

// ID gets the id of this subtype
func (m *GaugeWidget) ID() int32 {
	return m.idField
}

// SetID sets the id of this subtype
func (m *GaugeWidget) SetID(val int32) {
	m.idField = val
}

// Interval gets the interval of this subtype
func (m *GaugeWidget) Interval() int32 {
	return m.intervalField
}

// SetInterval sets the interval of this subtype
func (m *GaugeWidget) SetInterval(val int32) {
	m.intervalField = val
}

// LastUpdatedBy gets the last updated by of this subtype
func (m *GaugeWidget) LastUpdatedBy() string {
	return m.lastUpdatedByField
}

// SetLastUpdatedBy sets the last updated by of this subtype
func (m *GaugeWidget) SetLastUpdatedBy(val string) {
	m.lastUpdatedByField = val
}

// LastUpdatedOn gets the last updated on of this subtype
func (m *GaugeWidget) LastUpdatedOn() int64 {
	return m.lastUpdatedOnField
}

// SetLastUpdatedOn sets the last updated on of this subtype
func (m *GaugeWidget) SetLastUpdatedOn(val int64) {
	m.lastUpdatedOnField = val
}

// Name gets the name of this subtype
func (m *GaugeWidget) Name() *string {
	return m.nameField
}

// SetName sets the name of this subtype
func (m *GaugeWidget) SetName(val *string) {
	m.nameField = val
}

// Theme gets the theme of this subtype
func (m *GaugeWidget) Theme() string {
	return m.themeField
}

// SetTheme sets the theme of this subtype
func (m *GaugeWidget) SetTheme(val string) {
	m.themeField = val
}

// Timescale gets the timescale of this subtype
func (m *GaugeWidget) Timescale() string {
	return m.timescaleField
}

// SetTimescale sets the timescale of this subtype
func (m *GaugeWidget) SetTimescale(val string) {
	m.timescaleField = val
}

// Type gets the type of this subtype
func (m *GaugeWidget) Type() string {
	return "gauge"
}

// SetType sets the type of this subtype
func (m *GaugeWidget) SetType(val string) {

}

// UserPermission gets the user permission of this subtype
func (m *GaugeWidget) UserPermission() string {
	return m.userPermissionField
}

// SetUserPermission sets the user permission of this subtype
func (m *GaugeWidget) SetUserPermission(val string) {
	m.userPermissionField = val
}

// ColorThresholds gets the color thresholds of this subtype

// DataPoint gets the data point of this subtype

// DisplayType gets the display type of this subtype

// DisplayUnit gets the display unit of this subtype

// Legend gets the legend of this subtype

// MaxValue gets the max value of this subtype

// MinValue gets the min value of this subtype

// PeakTimeRange gets the peak time range of this subtype

// ShowPeak gets the show peak of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *GaugeWidget) UnmarshalJSON(raw []byte) error {
	var data struct {

		// The threshold of Gauge color changes
		ColorThresholds []*ColorThreshold `json:"colorThresholds"`

		// The datapoint whose value is displayed in the gauge widget
		// Required: true
		DataPoint *GaugeDataPoint `json:"dataPoint"`

		// Display as "Raw Value" or "Percent"
		DisplayType int32 `json:"displayType,omitempty"`

		// The unit for the raw value
		DisplayUnit string `json:"displayUnit,omitempty"`

		// The legend for the widget, displayed underneath the gauge
		Legend string `json:"legend,omitempty"`

		// The maximum value of the gauge widget, displayed on the right side of the gauge
		MaxValue float64 `json:"maxValue,omitempty"`

		// The minimum value of the gauge widget, displayed on the left side of the gauge
		MinValue float64 `json:"minValue,omitempty"`

		// The time range over which the peak value is determined
		PeakTimeRange string `json:"peakTimeRange,omitempty"`

		// Whether or not the peak value is displayed on the gauge widget
		ShowPeak bool `json:"showPeak,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var base struct {
		/* Just the base type fields. Used for unmashalling polymorphic types.*/

		DashboardID *int32 `json:"dashboardId"`

		Description string `json:"description,omitempty"`

		ID int32 `json:"id,omitempty"`

		Interval int32 `json:"interval,omitempty"`

		LastUpdatedBy string `json:"lastUpdatedBy,omitempty"`

		LastUpdatedOn int64 `json:"lastUpdatedOn,omitempty"`

		Name *string `json:"name"`

		Theme string `json:"theme,omitempty"`

		Timescale string `json:"timescale,omitempty"`

		Type string `json:"type"`

		UserPermission string `json:"userPermission,omitempty"`
	}
	buf = bytes.NewBuffer(raw)
	dec = json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&base); err != nil {
		return err
	}

	var result GaugeWidget

	result.dashboardIdField = base.DashboardID

	result.descriptionField = base.Description

	result.idField = base.ID

	result.intervalField = base.Interval

	result.lastUpdatedByField = base.LastUpdatedBy

	result.lastUpdatedOnField = base.LastUpdatedOn

	result.nameField = base.Name

	result.themeField = base.Theme

	result.timescaleField = base.Timescale

	if base.Type != result.Type() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid type value: %q", base.Type)
	}

	result.userPermissionField = base.UserPermission

	result.ColorThresholds = data.ColorThresholds

	result.DataPoint = data.DataPoint

	result.DisplayType = data.DisplayType

	result.DisplayUnit = data.DisplayUnit

	result.Legend = data.Legend

	result.MaxValue = data.MaxValue

	result.MinValue = data.MinValue

	result.PeakTimeRange = data.PeakTimeRange

	result.ShowPeak = data.ShowPeak

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m GaugeWidget) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// The threshold of Gauge color changes
		ColorThresholds []*ColorThreshold `json:"colorThresholds"`

		// The datapoint whose value is displayed in the gauge widget
		// Required: true
		DataPoint *GaugeDataPoint `json:"dataPoint"`

		// Display as "Raw Value" or "Percent"
		DisplayType int32 `json:"displayType,omitempty"`

		// The unit for the raw value
		DisplayUnit string `json:"displayUnit,omitempty"`

		// The legend for the widget, displayed underneath the gauge
		Legend string `json:"legend,omitempty"`

		// The maximum value of the gauge widget, displayed on the right side of the gauge
		MaxValue float64 `json:"maxValue,omitempty"`

		// The minimum value of the gauge widget, displayed on the left side of the gauge
		MinValue float64 `json:"minValue,omitempty"`

		// The time range over which the peak value is determined
		PeakTimeRange string `json:"peakTimeRange,omitempty"`

		// Whether or not the peak value is displayed on the gauge widget
		ShowPeak bool `json:"showPeak,omitempty"`
	}{

		ColorThresholds: m.ColorThresholds,

		DataPoint: m.DataPoint,

		DisplayType: m.DisplayType,

		DisplayUnit: m.DisplayUnit,

		Legend: m.Legend,

		MaxValue: m.MaxValue,

		MinValue: m.MinValue,

		PeakTimeRange: m.PeakTimeRange,

		ShowPeak: m.ShowPeak,
	},
	)
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		DashboardID *int32 `json:"dashboardId"`

		Description string `json:"description,omitempty"`

		ID int32 `json:"id,omitempty"`

		Interval int32 `json:"interval,omitempty"`

		LastUpdatedBy string `json:"lastUpdatedBy,omitempty"`

		LastUpdatedOn int64 `json:"lastUpdatedOn,omitempty"`

		Name *string `json:"name"`

		Theme string `json:"theme,omitempty"`

		Timescale string `json:"timescale,omitempty"`

		Type string `json:"type"`

		UserPermission string `json:"userPermission,omitempty"`
	}{

		DashboardID: m.DashboardID(),

		Description: m.Description(),

		ID: m.ID(),

		Interval: m.Interval(),

		LastUpdatedBy: m.LastUpdatedBy(),

		LastUpdatedOn: m.LastUpdatedOn(),

		Name: m.Name(),

		Theme: m.Theme(),

		Timescale: m.Timescale(),

		Type: m.Type(),

		UserPermission: m.UserPermission(),
	},
	)
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this gauge widget
func (m *GaugeWidget) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDashboardID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateColorThresholds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDataPoint(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *GaugeWidget) validateDashboardID(formats strfmt.Registry) error {

	if err := validate.Required("dashboardId", "body", m.DashboardID()); err != nil {
		return err
	}

	return nil
}

func (m *GaugeWidget) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name()); err != nil {
		return err
	}

	return nil
}

func (m *GaugeWidget) validateColorThresholds(formats strfmt.Registry) error {

	if swag.IsZero(m.ColorThresholds) { // not required
		return nil
	}

	for i := 0; i < len(m.ColorThresholds); i++ {
		if swag.IsZero(m.ColorThresholds[i]) { // not required
			continue
		}

		if m.ColorThresholds[i] != nil {
			if err := m.ColorThresholds[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("colorThresholds" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *GaugeWidget) validateDataPoint(formats strfmt.Registry) error {

	if err := validate.Required("dataPoint", "body", m.DataPoint); err != nil {
		return err
	}

	if m.DataPoint != nil {
		if err := m.DataPoint.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("dataPoint")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *GaugeWidget) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *GaugeWidget) UnmarshalBinary(b []byte) error {
	var res GaugeWidget
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}