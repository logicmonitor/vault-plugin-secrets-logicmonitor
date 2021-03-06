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

type GraphPlotLine struct {
	ColorName string `json:"colorName,omitempty"`
	Std float64 `json:"std,omitempty"`
	Visible bool `json:"visible,omitempty"`
	Color string `json:"color,omitempty"`
	Data []float64 `json:"data,omitempty"`
	Max float64 `json:"max,omitempty"`
	Legend string `json:"legend,omitempty"`
	Description string `json:"description,omitempty"`
	Label string `json:"label,omitempty"`
	Type_ string `json:"type,omitempty"`
	Min float64 `json:"min,omitempty"`
	Avg float64 `json:"avg,omitempty"`
	Decimal int32 `json:"decimal,omitempty"`
	UseYMax bool `json:"useYMax,omitempty"`
}
