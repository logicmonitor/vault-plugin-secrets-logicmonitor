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

type DashboardBase struct {
	Owner string `json:"owner,omitempty"`
	Template *JsonObject `json:"template,omitempty"`
	UserPermission string `json:"userPermission,omitempty"`
	GroupId int32 `json:"groupId,omitempty"`
	FullName string `json:"fullName,omitempty"`
	Description string `json:"description,omitempty"`
	Sharable bool `json:"sharable,omitempty"`
	WidgetsOrder string `json:"widgetsOrder,omitempty"`
	WidgetsConfig *JsonObject `json:"widgetsConfig,omitempty"`
	GroupName string `json:"groupName,omitempty"`
	WidgetTokens []WidgetToken `json:"widgetTokens,omitempty"`
	Name string `json:"name"`
	Id int32 `json:"id,omitempty"`
	GroupFullPath string `json:"groupFullPath,omitempty"`
}
