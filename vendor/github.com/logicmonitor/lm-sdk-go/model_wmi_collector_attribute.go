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

type WmiCollectorAttribute struct {
	Name string `json:"name"`
	MethodInputs string `json:"methodInputs"`
	Ip string `json:"ip,omitempty"`
	Namespace string `json:"namespace"`
	MethodName string `json:"methodName"`
	TargetPath string `json:"targetPath"`
	QueryClass string `json:"queryClass"`
	QueryIndex string `json:"queryIndex"`
	QueryValue string `json:"queryValue"`
	Type_ string `json:"type"`
}
