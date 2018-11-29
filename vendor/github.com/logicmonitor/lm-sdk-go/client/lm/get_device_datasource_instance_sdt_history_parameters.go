// Code generated by go-swagger; DO NOT EDIT.

package lm

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"
)

// NewGetDeviceDatasourceInstanceSDTHistoryParams creates a new GetDeviceDatasourceInstanceSDTHistoryParams object
// with the default values initialized.
func NewGetDeviceDatasourceInstanceSDTHistoryParams() *GetDeviceDatasourceInstanceSDTHistoryParams {
	var ()
	return &GetDeviceDatasourceInstanceSDTHistoryParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetDeviceDatasourceInstanceSDTHistoryParamsWithTimeout creates a new GetDeviceDatasourceInstanceSDTHistoryParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetDeviceDatasourceInstanceSDTHistoryParamsWithTimeout(timeout time.Duration) *GetDeviceDatasourceInstanceSDTHistoryParams {
	var ()
	return &GetDeviceDatasourceInstanceSDTHistoryParams{

		timeout: timeout,
	}
}

// NewGetDeviceDatasourceInstanceSDTHistoryParamsWithContext creates a new GetDeviceDatasourceInstanceSDTHistoryParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetDeviceDatasourceInstanceSDTHistoryParamsWithContext(ctx context.Context) *GetDeviceDatasourceInstanceSDTHistoryParams {
	var ()
	return &GetDeviceDatasourceInstanceSDTHistoryParams{

		Context: ctx,
	}
}

// NewGetDeviceDatasourceInstanceSDTHistoryParamsWithHTTPClient creates a new GetDeviceDatasourceInstanceSDTHistoryParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetDeviceDatasourceInstanceSDTHistoryParamsWithHTTPClient(client *http.Client) *GetDeviceDatasourceInstanceSDTHistoryParams {
	var ()
	return &GetDeviceDatasourceInstanceSDTHistoryParams{
		HTTPClient: client,
	}
}

/*GetDeviceDatasourceInstanceSDTHistoryParams contains all the parameters to send to the API endpoint
for the get device datasource instance SDT history operation typically these are written to a http.Request
*/
type GetDeviceDatasourceInstanceSDTHistoryParams struct {

	/*DeviceID*/
	DeviceID int32
	/*HdsID
	  The device-datasource ID

	*/
	HdsID int32
	/*ID*/
	ID int32

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithTimeout(timeout time.Duration) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithContext(ctx context.Context) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithHTTPClient(client *http.Client) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDeviceID adds the deviceID to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithDeviceID(deviceID int32) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetDeviceID(deviceID)
	return o
}

// SetDeviceID adds the deviceId to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetDeviceID(deviceID int32) {
	o.DeviceID = deviceID
}

// WithHdsID adds the hdsID to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithHdsID(hdsID int32) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetHdsID(hdsID)
	return o
}

// SetHdsID adds the hdsId to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetHdsID(hdsID int32) {
	o.HdsID = hdsID
}

// WithID adds the id to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WithID(id int32) *GetDeviceDatasourceInstanceSDTHistoryParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get device datasource instance SDT history params
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) SetID(id int32) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetDeviceDatasourceInstanceSDTHistoryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param deviceId
	if err := r.SetPathParam("deviceId", swag.FormatInt32(o.DeviceID)); err != nil {
		return err
	}

	// path param hdsId
	if err := r.SetPathParam("hdsId", swag.FormatInt32(o.HdsID)); err != nil {
		return err
	}

	// path param id
	if err := r.SetPathParam("id", swag.FormatInt32(o.ID)); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
