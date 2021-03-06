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

type GroupNetFlowRecord struct {
	DataType string `json:"dataType,omitempty"`
	SrcIP string `json:"srcIP,omitempty"`
	PercentUsage float64 `json:"percentUsage,omitempty"`
	LastEpochInSec int64 `json:"lastEpochInSec,omitempty"`
	IfOut int64 `json:"ifOut,omitempty"`
	Usage float64 `json:"usage,omitempty"`
	DstDNS string `json:"dstDNS,omitempty"`
	SrcPort int32 `json:"srcPort,omitempty"`
	DeviceDisplayName string `json:"deviceDisplayName,omitempty"`
	FirstEpochInSec int64 `json:"firstEpochInSec,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	DstPort int32 `json:"dstPort,omitempty"`
	IfIn int64 `json:"ifIn,omitempty"`
	SourceMBytes float64 `json:"sourceMBytes,omitempty"`
	SrcDNS string `json:"srcDNS,omitempty"`
	DestinationMBytes float64 `json:"destinationMBytes,omitempty"`
	DstIP string `json:"dstIP,omitempty"`
}
