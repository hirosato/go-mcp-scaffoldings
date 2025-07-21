package response

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// SuccessResponse represents a success response
type SuccessResponse struct {
	Success    bool             `json:"success"`
	Data       interface{}      `json:"data"`
	Metadata   ResponseMetadata `json:"metadata"`
	Pagination *Pagination      `json:"pagination,omitempty"`
}

// ResponseMetadata represents the metadata for responses
type ResponseMetadata struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	RequestID string `json:"requestId,omitempty"`
}

// Pagination represents pagination information
type Pagination struct {
	Total      int    `json:"total"`
	Page       int    `json:"page,omitempty"`
	PerPage    int    `json:"perPage,omitempty"`
	TotalPages int    `json:"totalPages,omitempty"`
	NextToken  string `json:"nextToken,omitempty"`
}

// DefaultHeaders returns the default headers for all responses
func DefaultHeaders() map[string]string {
	return map[string]string{
		"Content-Type":                 "application/json",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Tenant-Id",
		"Access-Control-Allow-Methods": "OPTIONS,GET,POST,PUT,DELETE",
	}
}

func RawSuccess(data interface{}, statusCode int, requestID string) events.APIGatewayProxyResponse {
	// Convert the response to JSON
	body, err := json.Marshal(data)
	if err != nil {
		// Fallback for JSON marshaling errors
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"success":false,"error":"INTERNAL_ERROR","error_description":{"message":"Failed to marshal paginated response"}}`,
			Headers:    DefaultHeaders(),
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Body:       string(body),
		Headers:    DefaultHeaders(),
	}
}

// Success creates a success response
func Success(data interface{}, statusCode int, requestID string) events.APIGatewayProxyResponse {
	// Create the response body
	response := SuccessResponse{
		Success: true,
		Data:    data,
		Metadata: ResponseMetadata{
			Version:   "1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			RequestID: requestID,
		},
	}
	return RawSuccess(response, statusCode, requestID)
}

// SuccessWithPagination creates a success response with pagination information
func SuccessWithPagination(data interface{}, pagination *Pagination, statusCode int, requestID string) events.APIGatewayProxyResponse {
	// Create the response body
	response := SuccessResponse{
		Success: true,
		Data:    data,
		Metadata: ResponseMetadata{
			Version:   "1.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			RequestID: requestID,
		},
		Pagination: pagination,
	}

	// Convert the response to JSON
	body, err := json.Marshal(response)
	if err != nil {
		// Fallback for JSON marshaling errors
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"success":false,"error":"INTERNAL_ERROR","error_description":{"message":"Failed to marshal paginated response"}}`,
			Headers:    DefaultHeaders(),
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Body:       string(body),
		Headers:    DefaultHeaders(),
	}
}

// OK creates a standard OK (200) response
func OK(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return Success(data, http.StatusOK, requestID)
}

// Created creates a standard Created (201) response
func Created(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return Success(data, http.StatusCreated, requestID)
}

// Accepted creates a standard Accepted (202) response
func Accepted(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return Success(data, http.StatusAccepted, requestID)
}

// OK creates a standard OK (200) response
func RawOK(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return RawSuccess(data, http.StatusOK, requestID)
}

// Created creates a standard Created (201) response
func RawCreated(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return RawSuccess(data, http.StatusCreated, requestID)
}

// Accepted creates a standard Accepted (202) response
func RawAccepted(data interface{}, requestID string) events.APIGatewayProxyResponse {
	return RawSuccess(data, http.StatusAccepted, requestID)
}

// NoContent creates a standard No Content (204) response
func NoContent() events.APIGatewayProxyResponse {
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusNoContent,
		Headers:    DefaultHeaders(),
	}
}

// JSON creates a response with the given status code and data directly serialized as JSON
func JSON(statusCode int, data interface{}, requestID string) events.APIGatewayProxyResponse {
	body, err := json.Marshal(data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"Failed to marshal JSON response"}}`,
			Headers:    DefaultHeaders(),
		}
	}

	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Body:       string(body),
		Headers:    DefaultHeaders(),
	}
}

// WriteJSON writes a JSON response directly to an http.ResponseWriter
func WriteJSON(w http.ResponseWriter, statusCode int, data any) {
	body, err := json.Marshal(data)
	if err != nil {
		// Handle marshaling error
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		errResp := `{"success":false,"error":"INTERNAL_ERROR","error_description":{"message":"Failed to marshal paginated response"}}`
		w.Write([]byte(errResp))
		return
	}

	// Set response headers
	for key, value := range DefaultHeaders() {
		w.Header().Set(key, value)
	}

	// Write status code and response body
	w.WriteHeader(statusCode)
	w.Write(body)
}

// WriteNoContent writes a No Content (204) response to the provided writer
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}
