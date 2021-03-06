/*
 * logicmonitor_sdk
 *
 * LogicMonitor is a SaaS-based performance monitoring platform that provides full visibility into complex, hybrid infrastructures, offering granular performance monitoring and actionable data and insights. logicmonitor_sdk enables you to manage your LogicMonitor account programmatically.
 *
 * API version: 1.0.0
 * Contact: sdk@logicmonitor.com
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */

package logicmonitor

type BatchJobWidget struct {
	RowSpan int32 `json:"rowSpan,omitempty"`
	LastUpdatedBy string `json:"lastUpdatedBy,omitempty"`
	UserPermission string `json:"userPermission,omitempty"`
	BatchJobId int32 `json:"batchJobId,omitempty"`
	ColSpan int32 `json:"colSpan,omitempty"`
	Description string `json:"description,omitempty"`
	Type_ string `json:"type"`
	BatchJobName string `json:"batchJobName,omitempty"`
	DeviceDisplayName string `json:"deviceDisplayName,omitempty"`
	GroupDisplayName string `json:"groupDisplayName,omitempty"`
	ColumnIdx int32 `json:"columnIdx,omitempty"`
	DashboardId int32 `json:"dashboardId"`
	Extra string `json:"extra,omitempty"`
	Name string `json:"name"`
	LastUpdatedOn int64 `json:"lastUpdatedOn,omitempty"`
	Theme string `json:"theme,omitempty"`
	Interval int32 `json:"interval,omitempty"`
	Id int32 `json:"id,omitempty"`
	Timescale string `json:"timescale,omitempty"`
	Order int32 `json:"order,omitempty"`
}
