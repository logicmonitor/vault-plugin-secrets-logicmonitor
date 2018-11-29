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

	models "github.com/logicmonitor/lm-sdk-go/models"
)

// NewUpdateCollectorByIDParams creates a new UpdateCollectorByIDParams object
// with the default values initialized.
func NewUpdateCollectorByIDParams() *UpdateCollectorByIDParams {
	var ()
	return &UpdateCollectorByIDParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateCollectorByIDParamsWithTimeout creates a new UpdateCollectorByIDParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateCollectorByIDParamsWithTimeout(timeout time.Duration) *UpdateCollectorByIDParams {
	var ()
	return &UpdateCollectorByIDParams{

		timeout: timeout,
	}
}

// NewUpdateCollectorByIDParamsWithContext creates a new UpdateCollectorByIDParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateCollectorByIDParamsWithContext(ctx context.Context) *UpdateCollectorByIDParams {
	var ()
	return &UpdateCollectorByIDParams{

		Context: ctx,
	}
}

// NewUpdateCollectorByIDParamsWithHTTPClient creates a new UpdateCollectorByIDParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateCollectorByIDParamsWithHTTPClient(client *http.Client) *UpdateCollectorByIDParams {
	var ()
	return &UpdateCollectorByIDParams{
		HTTPClient: client,
	}
}

/*UpdateCollectorByIDParams contains all the parameters to send to the API endpoint
for the update collector by Id operation typically these are written to a http.Request
*/
type UpdateCollectorByIDParams struct {

	/*Body*/
	Body *models.Collector
	/*ID*/
	ID int32

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update collector by Id params
func (o *UpdateCollectorByIDParams) WithTimeout(timeout time.Duration) *UpdateCollectorByIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update collector by Id params
func (o *UpdateCollectorByIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update collector by Id params
func (o *UpdateCollectorByIDParams) WithContext(ctx context.Context) *UpdateCollectorByIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update collector by Id params
func (o *UpdateCollectorByIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update collector by Id params
func (o *UpdateCollectorByIDParams) WithHTTPClient(client *http.Client) *UpdateCollectorByIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update collector by Id params
func (o *UpdateCollectorByIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update collector by Id params
func (o *UpdateCollectorByIDParams) WithBody(body *models.Collector) *UpdateCollectorByIDParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update collector by Id params
func (o *UpdateCollectorByIDParams) SetBody(body *models.Collector) {
	o.Body = body
}

// WithID adds the id to the update collector by Id params
func (o *UpdateCollectorByIDParams) WithID(id int32) *UpdateCollectorByIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the update collector by Id params
func (o *UpdateCollectorByIDParams) SetID(id int32) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateCollectorByIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
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
