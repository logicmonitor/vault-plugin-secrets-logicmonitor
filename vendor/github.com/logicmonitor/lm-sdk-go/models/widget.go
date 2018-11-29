// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/validate"
)

// Widget widget
// swagger:discriminator Widget type
type Widget interface {
	runtime.Validatable

	// The id of the dashboard the widget belongs to
	// Required: true
	DashboardID() *int32
	SetDashboardID(*int32)

	// The description of the widget
	Description() string
	SetDescription(string)

	// The Id of the widget
	ID() int32
	SetID(int32)

	// The refresh interval of the widget, in minutes
	Interval() int32
	SetInterval(int32)

	// The user that last updated the widget
	// Read Only: true
	LastUpdatedBy() string
	SetLastUpdatedBy(string)

	// The time that corresponds to when the widget was last updated, in epoch format
	// Read Only: true
	LastUpdatedOn() int64
	SetLastUpdatedOn(int64)

	// The name of the widget
	// Required: true
	Name() *string
	SetName(*string)

	// The color scheme of the widget. Options are: borderPurple | borderGray | borderBlue | solidPurple | solidGray | solidBlue | simplePurple | simpleBlue | simpleGray | newBorderGray | newBorderBlue | newBorderDarkBlue | newSolidGray | newSolidBlue | newSolidDarkBlue | newSimpleGray | newSimpleBlue |newSimpleDarkBlue
	Theme() string
	SetTheme(string)

	// The default timescale of the widget
	Timescale() string
	SetTimescale(string)

	// alert | deviceNOC | html | serviceOverallStatus | sgraph | ngraph | serviceNOC | serviceSLA | bigNumber | gmap | serviceIndividualStatus | gauge | pieChart | ngraph | batchjob
	// Required: true
	Type() string
	SetType(string)

	// The permission level of the user who last modified the widget
	// Read Only: true
	UserPermission() string
	SetUserPermission(string)
}

type widget struct {
	dashboardIdField *int32

	descriptionField string

	idField int32

	intervalField int32

	lastUpdatedByField string

	lastUpdatedOnField int64

	nameField *string

	themeField string

	timescaleField string

	typeField string

	userPermissionField string
}

// DashboardID gets the dashboard Id of this polymorphic type
func (m *widget) DashboardID() *int32 {
	return m.dashboardIdField
}

// SetDashboardID sets the dashboard Id of this polymorphic type
func (m *widget) SetDashboardID(val *int32) {
	m.dashboardIdField = val
}

// Description gets the description of this polymorphic type
func (m *widget) Description() string {
	return m.descriptionField
}

// SetDescription sets the description of this polymorphic type
func (m *widget) SetDescription(val string) {
	m.descriptionField = val
}

// ID gets the id of this polymorphic type
func (m *widget) ID() int32 {
	return m.idField
}

// SetID sets the id of this polymorphic type
func (m *widget) SetID(val int32) {
	m.idField = val
}

// Interval gets the interval of this polymorphic type
func (m *widget) Interval() int32 {
	return m.intervalField
}

// SetInterval sets the interval of this polymorphic type
func (m *widget) SetInterval(val int32) {
	m.intervalField = val
}

// LastUpdatedBy gets the last updated by of this polymorphic type
func (m *widget) LastUpdatedBy() string {
	return m.lastUpdatedByField
}

// SetLastUpdatedBy sets the last updated by of this polymorphic type
func (m *widget) SetLastUpdatedBy(val string) {
	m.lastUpdatedByField = val
}

// LastUpdatedOn gets the last updated on of this polymorphic type
func (m *widget) LastUpdatedOn() int64 {
	return m.lastUpdatedOnField
}

// SetLastUpdatedOn sets the last updated on of this polymorphic type
func (m *widget) SetLastUpdatedOn(val int64) {
	m.lastUpdatedOnField = val
}

// Name gets the name of this polymorphic type
func (m *widget) Name() *string {
	return m.nameField
}

// SetName sets the name of this polymorphic type
func (m *widget) SetName(val *string) {
	m.nameField = val
}

// Theme gets the theme of this polymorphic type
func (m *widget) Theme() string {
	return m.themeField
}

// SetTheme sets the theme of this polymorphic type
func (m *widget) SetTheme(val string) {
	m.themeField = val
}

// Timescale gets the timescale of this polymorphic type
func (m *widget) Timescale() string {
	return m.timescaleField
}

// SetTimescale sets the timescale of this polymorphic type
func (m *widget) SetTimescale(val string) {
	m.timescaleField = val
}

// Type gets the type of this polymorphic type
func (m *widget) Type() string {
	return "Widget"
}

// SetType sets the type of this polymorphic type
func (m *widget) SetType(val string) {

}

// UserPermission gets the user permission of this polymorphic type
func (m *widget) UserPermission() string {
	return m.userPermissionField
}

// SetUserPermission sets the user permission of this polymorphic type
func (m *widget) SetUserPermission(val string) {
	m.userPermissionField = val
}

// UnmarshalWidgetSlice unmarshals polymorphic slices of Widget
func UnmarshalWidgetSlice(reader io.Reader, consumer runtime.Consumer) ([]Widget, error) {
	var elements []json.RawMessage
	if err := consumer.Consume(reader, &elements); err != nil {
		return nil, err
	}

	var result []Widget
	for _, element := range elements {
		obj, err := unmarshalWidget(element, consumer)
		if err != nil {
			return nil, err
		}
		result = append(result, obj)
	}
	return result, nil
}

// UnmarshalWidget unmarshals polymorphic Widget
func UnmarshalWidget(reader io.Reader, consumer runtime.Consumer) (Widget, error) {
	// we need to read this twice, so first into a buffer
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return unmarshalWidget(data, consumer)
}

func unmarshalWidget(data []byte, consumer runtime.Consumer) (Widget, error) {
	buf := bytes.NewBuffer(data)
	buf2 := bytes.NewBuffer(data)

	// the first time this is read is to fetch the value of the type property.
	var getType struct {
		Type string `json:"type"`
	}
	if err := consumer.Consume(buf, &getType); err != nil {
		return nil, err
	}

	if err := validate.RequiredString("type", "body", getType.Type); err != nil {
		return nil, err
	}

	// The value of type is used to determine which type to create and unmarshal the data into
	switch getType.Type {
	case "Widget":
		var result widget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "alert":
		var result AlertWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "batchjob":
		var result BatchJobWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "bigNumber":
		var result BigNumberWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "cgraph":
		var result CustomerGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "deviceSLA":
		var result DeviceSLAWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "dynamicTable":
		var result DynamicTableWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "flash":
		var result FlashWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "gauge":
		var result GaugeWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "gmap":
		var result GoogleMapWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "groupNetflow":
		var result NetflowGroupWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "groupNetflowGraph":
		var result NetflowGroupGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "html":
		var result HTMLWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "netflow":
		var result NetflowWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "netflowgraph":
		var result NetflowGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "ngraph":
		var result NormalGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "noc":
		var result NOCWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "ograph":
		var result OverviewGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "pieChart":
		var result PieChartWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "sgraph":
		var result WebsiteGraphWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "statsd":
		var result StatsDWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "table":
		var result TableWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "text":
		var result TextWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "websiteIndividualStatus":
		var result WebsiteIndividualsStatusWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "websiteOverallStatus":
		var result WebsiteOverallStatusWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "websiteOverview":
		var result WebsiteOverviewWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	case "websiteSLA":
		var result WebsiteSLAWidget
		if err := consumer.Consume(buf2, &result); err != nil {
			return nil, err
		}
		return &result, nil

	}
	return nil, errors.New(422, "invalid type value: %q", getType.Type)

}

// Validate validates this widget
func (m *widget) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDashboardID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *widget) validateDashboardID(formats strfmt.Registry) error {

	if err := validate.Required("dashboardId", "body", m.DashboardID()); err != nil {
		return err
	}

	return nil
}

func (m *widget) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name()); err != nil {
		return err
	}

	return nil
}