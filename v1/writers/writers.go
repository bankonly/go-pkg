package writers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/bankonly/go-pkg/v1/stacktrace"
)

type Json struct {
	Data interface{} `json:"data"`
}

type MessageOpts struct {
	RequestId string `json:"-"`
	Message   string `json:"message"`
}

type Writers interface {
	Status(code int)
	JSON(data interface{})
	Message(data string)
	ParseError(err error)
	BadRequest(message string)
	NotFound(message string)
	InternalServerError(message string)
	Forbidden(message string)
	Unauthorized(message string)
	TooManyRequest(message string)
	Header(string, string)
	Write([]byte)
	RequestId() string
}

type WriterOpts struct {
	w    http.ResponseWriter
	r    *http.Request
	code int
}

func New(w http.ResponseWriter, r *http.Request) Writers {
	w.Header().Set("Content-Type", "application/json")
	return &WriterOpts{w: w, r: r, code: 200}
}

func (opts *WriterOpts) RequestId() string {
	return opts.r.Context().Value(RequestLogKey).(string)
}

func (opts *WriterOpts) Write(data []byte) {
	opts.w.Header().Set("Request-Id", opts.RequestId())
	go PrintLog(opts.RequestId())
	opts.w.Write(data)
}

func (opts *WriterOpts) Header(key, value string) {
	opts.w.Header().Set(key, value)
}

func (opts *WriterOpts) Status(code int) {
	SetStatusCodeAndMessage(opts.RequestId(), opts.code, "")
	opts.code = code
}

// Response json
func (opts *WriterOpts) JSON(data interface{}) {
	opts.w.WriteHeader(opts.code)
	SetStatusCodeAndMessage(opts.RequestId(), opts.code, "")
	dt, _ := json.Marshal(data)
	opts.Write(dt)
}

// Response string
func (opts *WriterOpts) Message(data string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: data})
	opts.w.WriteHeader(opts.code)
	SetStatusCodeAndMessage(opts.RequestId(), opts.code, data)
	opts.Write(response)
}

// String response
func (opts *WriterOpts) BadRequest(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(400)
	SetStatusCodeAndMessage(opts.RequestId(), 400, message)
	opts.Write(response)
}

// String not found
func (opts *WriterOpts) NotFound(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(404)
	SetStatusCodeAndMessage(opts.RequestId(), 404, message)
	opts.Write(response)
}

// Http internal server error
func (opts *WriterOpts) InternalServerError(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(500)
	SetStatusCodeAndMessage(opts.RequestId(), 500, message)
	opts.Write(response)
}

// Http Forbidden
func (opts *WriterOpts) Forbidden(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(403)
	SetStatusCodeAndMessage(opts.RequestId(), 403, message)
	opts.Write(response)
}

// Http Forbidden
func (opts *WriterOpts) Unauthorized(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(401)
	SetStatusCodeAndMessage(opts.RequestId(), 401, message)
	opts.Write(response)
}

// Http Forbidden
func (opts *WriterOpts) TooManyRequest(message string) {
	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(429)
	SetStatusCodeAndMessage(opts.RequestId(), 429, message)
	opts.Write(response)
}

// Parser error
func (opts *WriterOpts) ParseError(err error) {
	statusCode := 500
	message := err.Error()

	// Split to get custom error
	customErrs := strings.Split(message, stacktrace.MatchString)
	if len(customErrs) > 1 {
		message = customErrs[1]

		// get error code
		if customErrCode, err := strconv.Atoi(customErrs[0]); err == nil {
			statusCode = customErrCode
		}
	}

	// Set error logs
	SetStatusCodeAndMessage(opts.RequestId(), statusCode, message)

	response, _ := json.Marshal(&MessageOpts{RequestId: opts.RequestId(), Message: message})
	opts.w.WriteHeader(statusCode)
	opts.Write(response)
}
