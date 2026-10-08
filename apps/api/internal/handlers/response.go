package handlers

import (
	"encoding/json"
	"net/http"
)

// StandardError represents an RFC 7807 problem details object.
type StandardError struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []interface{} `json:"details,omitempty"`
}

// ErrorResponse envelope.
type ErrorResponse struct {
	Status string        `json:"status"` // always "error"
	Error  StandardError `json:"error"`
}

// SuccessResponse envelope.
type SuccessResponse struct {
	Status string      `json:"status"` // always "success"
	Data   interface{} `json:"data"`
}

// WriteJSON sends a JSON response with status code and Content-Type header.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteError sends a standard error response envelope.
func WriteError(w http.ResponseWriter, status int, code, message string, details ...interface{}) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	resp := ErrorResponse{
		Status: "error",
		Error: StandardError{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}
