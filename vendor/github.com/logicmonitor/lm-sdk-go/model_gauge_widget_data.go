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

type GaugeWidgetData struct {
	MaxValue float64 `json:"maxValue,omitempty"`
	Legend string `json:"legend,omitempty"`
	PeakTime int64 `json:"peakTime,omitempty"`
	HistoryTimestamps []int64 `json:"historyTimestamps,omitempty"`
	DisplayUnit string `json:"displayUnit,omitempty"`
	Type_ string `json:"type,omitempty"`
	PeakTimeOnLocal string `json:"peakTimeOnLocal,omitempty"`
	ColorLevel int32 `json:"colorLevel,omitempty"`
	PeakValue float64 `json:"peakValue,omitempty"`
	MinValue float64 `json:"minValue,omitempty"`
	DisplayType int32 `json:"displayType,omitempty"`
	ShowPeak bool `json:"showPeak,omitempty"`
	CurrentValue float64 `json:"currentValue,omitempty"`
	HistoryValues []float64 `json:"historyValues,omitempty"`
}