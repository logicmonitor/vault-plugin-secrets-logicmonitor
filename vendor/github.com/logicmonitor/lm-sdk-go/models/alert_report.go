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

// AlertReport alert report
// swagger:model AlertReport
type AlertReport struct {
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

	// all | acked | nonacked
	// all: both acknowledged and non-acknowledged alerts that meet the report criteria will be displayed
	// acked: only acknowledged alerts that meet the report criteria will be displayed
	// nonacked: only non-acknowledged alerts that meet the report criteria will be displayed
	AckFilter string `json:"ackFilter,omitempty"`

	// true: only alerts that are still alerting (i.e. haven't yet cleared) will be displayed in the report
	// false: active alerts and cleared alerts will both be displayed in the report
	ActiveOnly bool `json:"activeOnly,omitempty"`

	// All alerts displayed in the report must have been routed to the Escalation Chains specified in this filter
	Chain string `json:"chain,omitempty"`

	// The columns that will be displayed in the report. You should specify the columns in the order in which you'd like them to be displayed. All column names need to be included in this object, but each column should have an associated isHidden field that indicates whether it is displayed or not. NOTE that if summaryOnly is set to true you can only include these columns: Alerts, Group, Device, Instance, Datapoint. If summaryOnly is set to false you can include these columns: Severity, Group, Device, Instance, Datapoint, Thresholds, Value, Began, End, Rule, Chain, Acked, Acked By, Acked On, Notes, In SDT
	Columns []*DynamicColumn `json:"columns"`

	// The group filter used to determine which alerts will appear in the report. Glob expression supported
	DataPoint string `json:"dataPoint,omitempty"`

	// All alerts displayed in the report must have been triggered for the Datasources specified in this filter
	DataSource string `json:"dataSource,omitempty"`

	// The instance filter used to determine which alerts will appear in the report. Glob expressions supported
	DataSourceInstanceName string `json:"dataSourceInstanceName,omitempty"`

	// The Time Range configured for the report. Options include: Last 2 hours | Last 24 hours | Last calendar day | Last 7 days | Last 14 days | Last 30 days | Last calendar month | Last 365 days | Any custom date range in this format: YYYY-MM-dd hh:mm TO YYYY-MM-dd hh:mm
	DateRange string `json:"dateRange,omitempty"`

	// The device filter used to determine which alerts will appear in the report. Glob expressions supported
	DeviceDisplayName string `json:"deviceDisplayName,omitempty"`

	// The group filter used to determine which alerts will appear in the report. Glob expressions supported
	GroupFullPath string `json:"groupFullPath,omitempty"`

	// true: alerts that started prior to the specified dateRange but that meet all other criteria will be displayed in the report
	// false: only alerts that started during the specified dateRange will be displayed in the report
	IncludePreexist bool `json:"includePreexist,omitempty"`

	// all | error | critical
	// all: alerts of all severity levels will be displayed if they match the filter criteria
	// error: only error and critical alerts that match the filter criteria will be displayed
	// critical: only critical alerts that match the filter criteria will be displayed
	Level string `json:"level,omitempty"`

	// All alerts displayed in the report must have been routed to the Rules specified in this filter
	Rule string `json:"rule,omitempty"`

	// all | sdt | nonsdt
	// all: alerts that are in SDT and that aren't in SDT that meet the report criteria will be displayed
	// sdt: only alerts that are in SDT and that meet the report criteria will be displayed
	// nonsdt: only alerts that aren't in SDT and that meet the report criteria will be displayed
	SDTFilter string `json:"sdtFilter,omitempty"`

	// count | host | dataPoint | level | startOn | ackedOn. How displayed alerts will be sorted in the report. Note that if summaryOnly is set to true, you are limited to sortedBy= count | host | dataPoint. If summaryOnly is set to false, you cannot set sortedBy = count
	SortedBy string `json:"sortedBy,omitempty"`

	// true: a column will be added to the report detailing the number of times each alert occurred
	// false: the number of times each alert occurred will not be displayed in the report
	SummaryOnly bool `json:"summaryOnly,omitempty"`

	// overlap | start - Any alerts active during the specified dateRange will be displayed in the report if time=overlap. If time=start, only alerts that started during the specified dateRange will be displayed in the report
	Timing string `json:"timing,omitempty"`
}

// CustomReportTypeID gets the custom report type Id of this subtype
func (m *AlertReport) CustomReportTypeID() int32 {
	return m.customReportTypeIdField
}

// SetCustomReportTypeID sets the custom report type Id of this subtype
func (m *AlertReport) SetCustomReportTypeID(val int32) {
	m.customReportTypeIdField = val
}

// CustomReportTypeName gets the custom report type name of this subtype
func (m *AlertReport) CustomReportTypeName() string {
	return m.customReportTypeNameField
}

// SetCustomReportTypeName sets the custom report type name of this subtype
func (m *AlertReport) SetCustomReportTypeName(val string) {
	m.customReportTypeNameField = val
}

// Delivery gets the delivery of this subtype
func (m *AlertReport) Delivery() string {
	return m.deliveryField
}

// SetDelivery sets the delivery of this subtype
func (m *AlertReport) SetDelivery(val string) {
	m.deliveryField = val
}

// Description gets the description of this subtype
func (m *AlertReport) Description() string {
	return m.descriptionField
}

// SetDescription sets the description of this subtype
func (m *AlertReport) SetDescription(val string) {
	m.descriptionField = val
}

// EnableViewAsOtherUser gets the enable view as other user of this subtype
func (m *AlertReport) EnableViewAsOtherUser() *bool {
	return m.enableViewAsOtherUserField
}

// SetEnableViewAsOtherUser sets the enable view as other user of this subtype
func (m *AlertReport) SetEnableViewAsOtherUser(val *bool) {
	m.enableViewAsOtherUserField = val
}

// Format gets the format of this subtype
func (m *AlertReport) Format() string {
	return m.formatField
}

// SetFormat sets the format of this subtype
func (m *AlertReport) SetFormat(val string) {
	m.formatField = val
}

// GroupID gets the group Id of this subtype
func (m *AlertReport) GroupID() int32 {
	return m.groupIdField
}

// SetGroupID sets the group Id of this subtype
func (m *AlertReport) SetGroupID(val int32) {
	m.groupIdField = val
}

// ID gets the id of this subtype
func (m *AlertReport) ID() int32 {
	return m.idField
}

// SetID sets the id of this subtype
func (m *AlertReport) SetID(val int32) {
	m.idField = val
}

// LastGenerateOn gets the last generate on of this subtype
func (m *AlertReport) LastGenerateOn() int64 {
	return m.lastGenerateOnField
}

// SetLastGenerateOn sets the last generate on of this subtype
func (m *AlertReport) SetLastGenerateOn(val int64) {
	m.lastGenerateOnField = val
}

// LastGeneratePages gets the last generate pages of this subtype
func (m *AlertReport) LastGeneratePages() int32 {
	return m.lastGeneratePagesField
}

// SetLastGeneratePages sets the last generate pages of this subtype
func (m *AlertReport) SetLastGeneratePages(val int32) {
	m.lastGeneratePagesField = val
}

// LastGenerateSize gets the last generate size of this subtype
func (m *AlertReport) LastGenerateSize() int64 {
	return m.lastGenerateSizeField
}

// SetLastGenerateSize sets the last generate size of this subtype
func (m *AlertReport) SetLastGenerateSize(val int64) {
	m.lastGenerateSizeField = val
}

// LastmodifyUserID gets the lastmodify user Id of this subtype
func (m *AlertReport) LastmodifyUserID() int32 {
	return m.lastmodifyUserIdField
}

// SetLastmodifyUserID sets the lastmodify user Id of this subtype
func (m *AlertReport) SetLastmodifyUserID(val int32) {
	m.lastmodifyUserIdField = val
}

// LastmodifyUserName gets the lastmodify user name of this subtype
func (m *AlertReport) LastmodifyUserName() string {
	return m.lastmodifyUserNameField
}

// SetLastmodifyUserName sets the lastmodify user name of this subtype
func (m *AlertReport) SetLastmodifyUserName(val string) {
	m.lastmodifyUserNameField = val
}

// Name gets the name of this subtype
func (m *AlertReport) Name() *string {
	return m.nameField
}

// SetName sets the name of this subtype
func (m *AlertReport) SetName(val *string) {
	m.nameField = val
}

// Recipients gets the recipients of this subtype
func (m *AlertReport) Recipients() []*ReportRecipient {
	return m.recipientsField
}

// SetRecipients sets the recipients of this subtype
func (m *AlertReport) SetRecipients(val []*ReportRecipient) {
	m.recipientsField = val
}

// ReportLinkNum gets the report link num of this subtype
func (m *AlertReport) ReportLinkNum() int32 {
	return m.reportLinkNumField
}

// SetReportLinkNum sets the report link num of this subtype
func (m *AlertReport) SetReportLinkNum(val int32) {
	m.reportLinkNumField = val
}

// Schedule gets the schedule of this subtype
func (m *AlertReport) Schedule() string {
	return m.scheduleField
}

// SetSchedule sets the schedule of this subtype
func (m *AlertReport) SetSchedule(val string) {
	m.scheduleField = val
}

// ScheduleTimezone gets the schedule timezone of this subtype
func (m *AlertReport) ScheduleTimezone() string {
	return m.scheduleTimezoneField
}

// SetScheduleTimezone sets the schedule timezone of this subtype
func (m *AlertReport) SetScheduleTimezone(val string) {
	m.scheduleTimezoneField = val
}

// Type gets the type of this subtype
func (m *AlertReport) Type() string {
	return "Alert"
}

// SetType sets the type of this subtype
func (m *AlertReport) SetType(val string) {

}

// UserPermission gets the user permission of this subtype
func (m *AlertReport) UserPermission() string {
	return m.userPermissionField
}

// SetUserPermission sets the user permission of this subtype
func (m *AlertReport) SetUserPermission(val string) {
	m.userPermissionField = val
}

// AckFilter gets the ack filter of this subtype

// ActiveOnly gets the active only of this subtype

// Chain gets the chain of this subtype

// Columns gets the columns of this subtype

// DataPoint gets the data point of this subtype

// DataSource gets the data source of this subtype

// DataSourceInstanceName gets the data source instance name of this subtype

// DateRange gets the date range of this subtype

// DeviceDisplayName gets the device display name of this subtype

// GroupFullPath gets the group full path of this subtype

// IncludePreexist gets the include preexist of this subtype

// Level gets the level of this subtype

// Rule gets the rule of this subtype

// SDTFilter gets the sdt filter of this subtype

// SortedBy gets the sorted by of this subtype

// SummaryOnly gets the summary only of this subtype

// Timing gets the timing of this subtype

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *AlertReport) UnmarshalJSON(raw []byte) error {
	var data struct {

		// all | acked | nonacked
		// all: both acknowledged and non-acknowledged alerts that meet the report criteria will be displayed
		// acked: only acknowledged alerts that meet the report criteria will be displayed
		// nonacked: only non-acknowledged alerts that meet the report criteria will be displayed
		AckFilter string `json:"ackFilter,omitempty"`

		// true: only alerts that are still alerting (i.e. haven't yet cleared) will be displayed in the report
		// false: active alerts and cleared alerts will both be displayed in the report
		ActiveOnly bool `json:"activeOnly,omitempty"`

		// All alerts displayed in the report must have been routed to the Escalation Chains specified in this filter
		Chain string `json:"chain,omitempty"`

		// The columns that will be displayed in the report. You should specify the columns in the order in which you'd like them to be displayed. All column names need to be included in this object, but each column should have an associated isHidden field that indicates whether it is displayed or not. NOTE that if summaryOnly is set to true you can only include these columns: Alerts, Group, Device, Instance, Datapoint. If summaryOnly is set to false you can include these columns: Severity, Group, Device, Instance, Datapoint, Thresholds, Value, Began, End, Rule, Chain, Acked, Acked By, Acked On, Notes, In SDT
		Columns []*DynamicColumn `json:"columns"`

		// The group filter used to determine which alerts will appear in the report. Glob expression supported
		DataPoint string `json:"dataPoint,omitempty"`

		// All alerts displayed in the report must have been triggered for the Datasources specified in this filter
		DataSource string `json:"dataSource,omitempty"`

		// The instance filter used to determine which alerts will appear in the report. Glob expressions supported
		DataSourceInstanceName string `json:"dataSourceInstanceName,omitempty"`

		// The Time Range configured for the report. Options include: Last 2 hours | Last 24 hours | Last calendar day | Last 7 days | Last 14 days | Last 30 days | Last calendar month | Last 365 days | Any custom date range in this format: YYYY-MM-dd hh:mm TO YYYY-MM-dd hh:mm
		DateRange string `json:"dateRange,omitempty"`

		// The device filter used to determine which alerts will appear in the report. Glob expressions supported
		DeviceDisplayName string `json:"deviceDisplayName,omitempty"`

		// The group filter used to determine which alerts will appear in the report. Glob expressions supported
		GroupFullPath string `json:"groupFullPath,omitempty"`

		// true: alerts that started prior to the specified dateRange but that meet all other criteria will be displayed in the report
		// false: only alerts that started during the specified dateRange will be displayed in the report
		IncludePreexist bool `json:"includePreexist,omitempty"`

		// all | error | critical
		// all: alerts of all severity levels will be displayed if they match the filter criteria
		// error: only error and critical alerts that match the filter criteria will be displayed
		// critical: only critical alerts that match the filter criteria will be displayed
		Level string `json:"level,omitempty"`

		// All alerts displayed in the report must have been routed to the Rules specified in this filter
		Rule string `json:"rule,omitempty"`

		// all | sdt | nonsdt
		// all: alerts that are in SDT and that aren't in SDT that meet the report criteria will be displayed
		// sdt: only alerts that are in SDT and that meet the report criteria will be displayed
		// nonsdt: only alerts that aren't in SDT and that meet the report criteria will be displayed
		SDTFilter string `json:"sdtFilter,omitempty"`

		// count | host | dataPoint | level | startOn | ackedOn. How displayed alerts will be sorted in the report. Note that if summaryOnly is set to true, you are limited to sortedBy= count | host | dataPoint. If summaryOnly is set to false, you cannot set sortedBy = count
		SortedBy string `json:"sortedBy,omitempty"`

		// true: a column will be added to the report detailing the number of times each alert occurred
		// false: the number of times each alert occurred will not be displayed in the report
		SummaryOnly bool `json:"summaryOnly,omitempty"`

		// overlap | start - Any alerts active during the specified dateRange will be displayed in the report if time=overlap. If time=start, only alerts that started during the specified dateRange will be displayed in the report
		Timing string `json:"timing,omitempty"`
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

	var result AlertReport

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

	result.AckFilter = data.AckFilter

	result.ActiveOnly = data.ActiveOnly

	result.Chain = data.Chain

	result.Columns = data.Columns

	result.DataPoint = data.DataPoint

	result.DataSource = data.DataSource

	result.DataSourceInstanceName = data.DataSourceInstanceName

	result.DateRange = data.DateRange

	result.DeviceDisplayName = data.DeviceDisplayName

	result.GroupFullPath = data.GroupFullPath

	result.IncludePreexist = data.IncludePreexist

	result.Level = data.Level

	result.Rule = data.Rule

	result.SDTFilter = data.SDTFilter

	result.SortedBy = data.SortedBy

	result.SummaryOnly = data.SummaryOnly

	result.Timing = data.Timing

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m AlertReport) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// all | acked | nonacked
		// all: both acknowledged and non-acknowledged alerts that meet the report criteria will be displayed
		// acked: only acknowledged alerts that meet the report criteria will be displayed
		// nonacked: only non-acknowledged alerts that meet the report criteria will be displayed
		AckFilter string `json:"ackFilter,omitempty"`

		// true: only alerts that are still alerting (i.e. haven't yet cleared) will be displayed in the report
		// false: active alerts and cleared alerts will both be displayed in the report
		ActiveOnly bool `json:"activeOnly,omitempty"`

		// All alerts displayed in the report must have been routed to the Escalation Chains specified in this filter
		Chain string `json:"chain,omitempty"`

		// The columns that will be displayed in the report. You should specify the columns in the order in which you'd like them to be displayed. All column names need to be included in this object, but each column should have an associated isHidden field that indicates whether it is displayed or not. NOTE that if summaryOnly is set to true you can only include these columns: Alerts, Group, Device, Instance, Datapoint. If summaryOnly is set to false you can include these columns: Severity, Group, Device, Instance, Datapoint, Thresholds, Value, Began, End, Rule, Chain, Acked, Acked By, Acked On, Notes, In SDT
		Columns []*DynamicColumn `json:"columns"`

		// The group filter used to determine which alerts will appear in the report. Glob expression supported
		DataPoint string `json:"dataPoint,omitempty"`

		// All alerts displayed in the report must have been triggered for the Datasources specified in this filter
		DataSource string `json:"dataSource,omitempty"`

		// The instance filter used to determine which alerts will appear in the report. Glob expressions supported
		DataSourceInstanceName string `json:"dataSourceInstanceName,omitempty"`

		// The Time Range configured for the report. Options include: Last 2 hours | Last 24 hours | Last calendar day | Last 7 days | Last 14 days | Last 30 days | Last calendar month | Last 365 days | Any custom date range in this format: YYYY-MM-dd hh:mm TO YYYY-MM-dd hh:mm
		DateRange string `json:"dateRange,omitempty"`

		// The device filter used to determine which alerts will appear in the report. Glob expressions supported
		DeviceDisplayName string `json:"deviceDisplayName,omitempty"`

		// The group filter used to determine which alerts will appear in the report. Glob expressions supported
		GroupFullPath string `json:"groupFullPath,omitempty"`

		// true: alerts that started prior to the specified dateRange but that meet all other criteria will be displayed in the report
		// false: only alerts that started during the specified dateRange will be displayed in the report
		IncludePreexist bool `json:"includePreexist,omitempty"`

		// all | error | critical
		// all: alerts of all severity levels will be displayed if they match the filter criteria
		// error: only error and critical alerts that match the filter criteria will be displayed
		// critical: only critical alerts that match the filter criteria will be displayed
		Level string `json:"level,omitempty"`

		// All alerts displayed in the report must have been routed to the Rules specified in this filter
		Rule string `json:"rule,omitempty"`

		// all | sdt | nonsdt
		// all: alerts that are in SDT and that aren't in SDT that meet the report criteria will be displayed
		// sdt: only alerts that are in SDT and that meet the report criteria will be displayed
		// nonsdt: only alerts that aren't in SDT and that meet the report criteria will be displayed
		SDTFilter string `json:"sdtFilter,omitempty"`

		// count | host | dataPoint | level | startOn | ackedOn. How displayed alerts will be sorted in the report. Note that if summaryOnly is set to true, you are limited to sortedBy= count | host | dataPoint. If summaryOnly is set to false, you cannot set sortedBy = count
		SortedBy string `json:"sortedBy,omitempty"`

		// true: a column will be added to the report detailing the number of times each alert occurred
		// false: the number of times each alert occurred will not be displayed in the report
		SummaryOnly bool `json:"summaryOnly,omitempty"`

		// overlap | start - Any alerts active during the specified dateRange will be displayed in the report if time=overlap. If time=start, only alerts that started during the specified dateRange will be displayed in the report
		Timing string `json:"timing,omitempty"`
	}{

		AckFilter: m.AckFilter,

		ActiveOnly: m.ActiveOnly,

		Chain: m.Chain,

		Columns: m.Columns,

		DataPoint: m.DataPoint,

		DataSource: m.DataSource,

		DataSourceInstanceName: m.DataSourceInstanceName,

		DateRange: m.DateRange,

		DeviceDisplayName: m.DeviceDisplayName,

		GroupFullPath: m.GroupFullPath,

		IncludePreexist: m.IncludePreexist,

		Level: m.Level,

		Rule: m.Rule,

		SDTFilter: m.SDTFilter,

		SortedBy: m.SortedBy,

		SummaryOnly: m.SummaryOnly,

		Timing: m.Timing,
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

// Validate validates this alert report
func (m *AlertReport) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRecipients(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateColumns(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AlertReport) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name()); err != nil {
		return err
	}

	return nil
}

func (m *AlertReport) validateRecipients(formats strfmt.Registry) error {

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

func (m *AlertReport) validateColumns(formats strfmt.Registry) error {

	if swag.IsZero(m.Columns) { // not required
		return nil
	}

	for i := 0; i < len(m.Columns); i++ {
		if swag.IsZero(m.Columns[i]) { // not required
			continue
		}

		if m.Columns[i] != nil {
			if err := m.Columns[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("columns" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *AlertReport) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AlertReport) UnmarshalBinary(b []byte) error {
	var res AlertReport
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
