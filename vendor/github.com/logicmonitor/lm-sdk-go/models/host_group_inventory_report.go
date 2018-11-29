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

// HostGroupInventoryReport host group inventory report
// swagger:model HostGroupInventoryReport
type HostGroupInventoryReport struct {
	customReportTypeIdField int32

	customReportTypeNameField string

	deliveryField string

	descriptionField string

	enableViewAsOtherUserField *bool

	formatField string

	groupIdField int32

	idField int32

	lastGenerateOnField int64

	lastGeneratePagesField int32

	lastGenerateSizeField int64

	lastmodifyUserIdField int32

	lastmodifyUserNameField string

	nameField *string

	recipientsField []*ReportRecipient

	reportLinkNumField int32

	scheduleField string

	scheduleTimezoneField string

	userPermissionField string

	// host groups
	HostGroups string `json:"hostGroups,omitempty"`

	// include sub groups
	IncludeSubGroups bool `json:"includeSubGroups,omitempty"`

	// properties
	// Required: true
	Properties []string `json:"properties"`

	// sorted by
	SortedBy string `json:"sortedBy,omitempty"`
}

// CustomReportTypeID gets the custom report type Id of this subtype
func (m *HostGroupInventoryReport) CustomReportTypeID() int32 {
	return m.customReportTypeIdField
}

// SetCustomReportTypeID sets the custom report type Id of this subtype
func (m *HostGroupInventoryReport) SetCustomReportTypeID(val int32) {
	m.customReportTypeIdField = val
}

// CustomReportTypeName gets the custom report type name of this subtype
func (m *HostGroupInventoryReport) CustomReportTypeName() string {
	return m.customReportTypeNameField
}

// SetCustomReportTypeName sets the custom report type name of this subtype
func (m *HostGroupInventoryReport) SetCustomReportTypeName(val string) {
	m.customReportTypeNameField = val
}

// Delivery gets the delivery of this subtype
func (m *HostGroupInventoryReport) Delivery() string {
	return m.deliveryField
}

// SetDelivery sets the delivery of this subtype
func (m *HostGroupInventoryReport) SetDelivery(val string) {
	m.deliveryField = val
}

// Description gets the description of this subtype
func (m *HostGroupInventoryReport) Description() string {
	return m.descriptionField
}

// SetDescription sets the description of this subtype
func (m *HostGroupInventoryReport) SetDescription(val string) {
	m.descriptionField = val
}

// EnableViewAsOtherUser gets the enable view as other user of this subtype
func (m *HostGroupInventoryReport) EnableViewAsOtherUser() *bool {
	return m.enableViewAsOtherUserField
}

// SetEnableViewAsOtherUser sets the enable view as other user of this subtype
func (m *HostGroupInventoryReport) SetEnableViewAsOtherUser(val *bool) {
	m.enableViewAsOtherUserField = val
}

// Format gets the format of this subtype
func (m *HostGroupInventoryReport) Format() string {
	return m.formatField
}

// SetFormat sets the format of this subtype
func (m *HostGroupInventoryReport) SetFormat(val string) {
	m.formatField = val
}

// GroupID gets the group Id of this subtype
func (m *HostGroupInventoryReport) GroupID() int32 {
	return m.groupIdField
}

// SetGroupID sets the group Id of this subtype
func (m *HostGroupInventoryReport) SetGroupID(val int32) {
	m.groupIdField = val
}

// ID gets the id of this subtype
func (m *HostGroupInventoryReport) ID() int32 {
	return m.idField
}

// SetID sets the id of this subtype
func (m *HostGroupInventoryReport) SetID(val int32) {
	m.idField = val
}

// LastGenerateOn gets the last generate on of this subtype
func (m *HostGroupInventoryReport) LastGenerateOn() int64 {
	return m.lastGenerateOnField
}

// SetLastGenerateOn sets the last generate on of this subtype
func (m *HostGroupInventoryReport) SetLastGenerateOn(val int64) {
	m.lastGenerateOnField = val
}

// LastGeneratePages gets the last generate pages of this subtype
func (m *HostGroupInventoryReport) LastGeneratePages() int32 {
	return m.lastGeneratePagesField
}

// SetLastGeneratePages sets the last generate pages of this subtype
func (m *HostGroupInventoryReport) SetLastGeneratePages(val int32) {
	m.lastGeneratePagesField = val
}

// LastGenerateSize gets the last generate size of this subtype
func (m *HostGroupInventoryReport) LastGenerateSize() int64 {
	return m.lastGenerateSizeField
}

// SetLastGenerateSize sets the last generate size of this subtype
func (m *HostGroupInventoryReport) SetLastGenerateSize(val int64) {
	m.lastGenerateSizeField = val
}

// LastmodifyUserID gets the lastmodify user Id of this subtype
func (m *HostGroupInventoryReport) LastmodifyUserID() int32 {
	return m.lastmodifyUserIdField
}

// SetLastmodifyUserID sets the lastmodify user Id of this subtype
func (m *HostGroupInventoryReport) SetLastmodifyUserID(val int32) {
	m.lastmodifyUserIdField = val
}

// LastmodifyUserName gets the lastmodify user name of this subtype
func (m *HostGroupInventoryReport) LastmodifyUserName() string {
	return m.lastmodifyUserNameField
}

// SetLastmodifyUserName sets the lastmodify user name of this subtype
func (m *HostGroupInventoryReport) SetLastmodifyUserName(val string) {
	m.lastmodifyUserNameField = val
}

// Name gets the name of this subtype
func (m *HostGroupInventoryReport) Name() *string {
	return m.nameField
}

// SetName sets the name of this subtype
func (m *HostGroupInventoryReport) SetName(val *string) {
	m.nameField = val
}

// Recipients gets the recipients of this subtype
func (m *HostGroupInventoryReport) Recipients() []*ReportRecipient {
	return m.recipientsField
}

// SetRecipients sets the recipients of this subtype
func (m *HostGroupInventoryReport) SetRecipients(val []*ReportRecipient) {
	m.recipientsField = val
}

// ReportLinkNum gets the report link num of this subtype
func (m *HostGroupInventoryReport) ReportLinkNum() int32 {
	return m.reportLinkNumField
}

// SetReportLinkNum sets the report link num of this subtype
func (m *HostGroupInventoryReport) SetReportLinkNum(val int32) {
	m.reportLinkNumField = val
}

// Schedule gets the schedule of this subtype
func (m *HostGroupInventoryReport) Schedule() string {
	return m.scheduleField
}

// SetSchedule sets the schedule of this subtype
func (m *HostGroupInventoryReport) SetSchedule(val string) {
	m.scheduleField = val
}

// ScheduleTimezone gets the schedule timezone of this subtype
func (m *HostGroupInventoryReport) ScheduleTimezone() string {
	return m.scheduleTimezoneField
}

// SetScheduleTimezone sets the schedule timezone of this subtype
func (m *HostGroupInventoryReport) SetScheduleTimezone(val string) {
	m.scheduleTimezoneField = val
}

// Type gets the type of this subtype
func (m *HostGroupInventoryReport) Type() string {
	return "Host group inventory"
}

// SetType sets the type of this subtype
func (m *HostGroupInventoryReport) SetType(val string) {

}

// UserPermission gets the user permission of this subtype
func (m *HostGroupInventoryReport) UserPermission() string {
	return m.userPermissionField
}

// SetUserPermission sets the user permission of this subtype
func (m *HostGroupInventoryReport) SetUserPermission(val string) {
	m.userPermissionField = val
}

// HostGroups gets the host groups of this subtype

// IncludeSubGroups gets the include sub groups of this subtype

// Properties gets the properties of this subtype

// SortedBy gets the sorted by of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *HostGroupInventoryReport) UnmarshalJSON(raw []byte) error {
	var data struct {

		// host groups
		HostGroups string `json:"hostGroups,omitempty"`

		// include sub groups
		IncludeSubGroups bool `json:"includeSubGroups,omitempty"`

		// properties
		// Required: true
		Properties []string `json:"properties"`

		// sorted by
		SortedBy string `json:"sortedBy,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var base struct {
		/* Just the base type fields. Used for unmashalling polymorphic types.*/

		CustomReportTypeID int32 `json:"customReportTypeId,omitempty"`

		CustomReportTypeName string `json:"customReportTypeName,omitempty"`

		Delivery string `json:"delivery,omitempty"`

		Description string `json:"description,omitempty"`

		EnableViewAsOtherUser *bool `json:"enableViewAsOtherUser,omitempty"`

		Format string `json:"format,omitempty"`

		GroupID int32 `json:"groupId,omitempty"`

		ID int32 `json:"id,omitempty"`

		LastGenerateOn int64 `json:"lastGenerateOn,omitempty"`

		LastGeneratePages int32 `json:"lastGeneratePages,omitempty"`

		LastGenerateSize int64 `json:"lastGenerateSize,omitempty"`

		LastmodifyUserID int32 `json:"lastmodifyUserId,omitempty"`

		LastmodifyUserName string `json:"lastmodifyUserName,omitempty"`

		Name *string `json:"name"`

		Recipients []*ReportRecipient `json:"recipients"`

		ReportLinkNum int32 `json:"reportLinkNum,omitempty"`

		Schedule string `json:"schedule,omitempty"`

		ScheduleTimezone string `json:"scheduleTimezone,omitempty"`

		Type string `json:"type"`

		UserPermission string `json:"userPermission,omitempty"`
	}
	buf = bytes.NewBuffer(raw)
	dec = json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&base); err != nil {
		return err
	}

	var result HostGroupInventoryReport

	result.customReportTypeIdField = base.CustomReportTypeID

	result.customReportTypeNameField = base.CustomReportTypeName

	result.deliveryField = base.Delivery

	result.descriptionField = base.Description

	result.enableViewAsOtherUserField = base.EnableViewAsOtherUser

	result.formatField = base.Format

	result.groupIdField = base.GroupID

	result.idField = base.ID

	result.lastGenerateOnField = base.LastGenerateOn

	result.lastGeneratePagesField = base.LastGeneratePages

	result.lastGenerateSizeField = base.LastGenerateSize

	result.lastmodifyUserIdField = base.LastmodifyUserID

	result.lastmodifyUserNameField = base.LastmodifyUserName

	result.nameField = base.Name

	result.recipientsField = base.Recipients

	result.reportLinkNumField = base.ReportLinkNum

	result.scheduleField = base.Schedule

	result.scheduleTimezoneField = base.ScheduleTimezone

	if base.Type != result.Type() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid type value: %q", base.Type)
	}

	result.userPermissionField = base.UserPermission

	result.HostGroups = data.HostGroups

	result.IncludeSubGroups = data.IncludeSubGroups

	result.Properties = data.Properties

	result.SortedBy = data.SortedBy

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m HostGroupInventoryReport) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// host groups
		HostGroups string `json:"hostGroups,omitempty"`

		// include sub groups
		IncludeSubGroups bool `json:"includeSubGroups,omitempty"`

		// properties
		// Required: true
		Properties []string `json:"properties"`

		// sorted by
		SortedBy string `json:"sortedBy,omitempty"`
	}{

		HostGroups: m.HostGroups,

		IncludeSubGroups: m.IncludeSubGroups,

		Properties: m.Properties,

		SortedBy: m.SortedBy,
	},
	)
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		CustomReportTypeID int32 `json:"customReportTypeId,omitempty"`

		CustomReportTypeName string `json:"customReportTypeName,omitempty"`

		Delivery string `json:"delivery,omitempty"`

		Description string `json:"description,omitempty"`

		EnableViewAsOtherUser *bool `json:"enableViewAsOtherUser,omitempty"`

		Format string `json:"format,omitempty"`

		GroupID int32 `json:"groupId,omitempty"`

		ID int32 `json:"id,omitempty"`

		LastGenerateOn int64 `json:"lastGenerateOn,omitempty"`

		LastGeneratePages int32 `json:"lastGeneratePages,omitempty"`

		LastGenerateSize int64 `json:"lastGenerateSize,omitempty"`

		LastmodifyUserID int32 `json:"lastmodifyUserId,omitempty"`

		LastmodifyUserName string `json:"lastmodifyUserName,omitempty"`

		Name *string `json:"name"`

		Recipients []*ReportRecipient `json:"recipients"`

		ReportLinkNum int32 `json:"reportLinkNum,omitempty"`

		Schedule string `json:"schedule,omitempty"`

		ScheduleTimezone string `json:"scheduleTimezone,omitempty"`

		Type string `json:"type"`

		UserPermission string `json:"userPermission,omitempty"`
	}{

		CustomReportTypeID: m.CustomReportTypeID(),

		CustomReportTypeName: m.CustomReportTypeName(),

		Delivery: m.Delivery(),

		Description: m.Description(),

		EnableViewAsOtherUser: m.EnableViewAsOtherUser(),

		Format: m.Format(),

		GroupID: m.GroupID(),

		ID: m.ID(),

		LastGenerateOn: m.LastGenerateOn(),

		LastGeneratePages: m.LastGeneratePages(),

		LastGenerateSize: m.LastGenerateSize(),

		LastmodifyUserID: m.LastmodifyUserID(),

		LastmodifyUserName: m.LastmodifyUserName(),

		Name: m.Name(),

		Recipients: m.Recipients(),

		ReportLinkNum: m.ReportLinkNum(),

		Schedule: m.Schedule(),

		ScheduleTimezone: m.ScheduleTimezone(),

		Type: m.Type(),

		UserPermission: m.UserPermission(),
	},
	)
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this host group inventory report
func (m *HostGroupInventoryReport) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecipients(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProperties(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *HostGroupInventoryReport) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name()); err != nil {
		return err
	}

	return nil
}

func (m *HostGroupInventoryReport) validateRecipients(formats strfmt.Registry) error {

	if swag.IsZero(m.Recipients()) { // not required
		return nil
	}

	for i := 0; i < len(m.Recipients()); i++ {
		if swag.IsZero(m.recipientsField[i]) { // not required
			continue
		}

		if m.recipientsField[i] != nil {
			if err := m.recipientsField[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("recipients" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *HostGroupInventoryReport) validateProperties(formats strfmt.Registry) error {

	if err := validate.Required("properties", "body", m.Properties); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *HostGroupInventoryReport) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HostGroupInventoryReport) UnmarshalBinary(b []byte) error {
	var res HostGroupInventoryReport
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}