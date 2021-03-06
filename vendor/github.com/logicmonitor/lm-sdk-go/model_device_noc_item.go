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

type DeviceNocItem struct {
	DataPointName string `json:"dataPointName"`
	InstanceName string `json:"instanceName"`
	Name string `json:"name"`
	DataSourceDisplayName string `json:"dataSourceDisplayName"`
	GroupBy string `json:"groupBy,omitempty"`
	DeviceGroupFullPath string `json:"deviceGroupFullPath"`
	DeviceDisplayName string `json:"deviceDisplayName"`
}
