package writers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bankonly/go-pkg/v1/common"
	"github.com/google/uuid"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type Key string

var RequestLogKey Key = "request-id"
var printer = message.NewPrinter(language.English)

type logInfo struct {
	RequestId    string      `json:"requestId"`
	ReqTime      time.Time   `json:"requestTime"`
	ResTime      time.Time   `json:"responseTime"`
	StatusCode   int         `json:"status_code"`
	ErrorMessage string      `json:"error_message"`
	ResTimeSec   string      `json:"responseTimeSec"`
	Host         string      `json:"host"`
	Method       string      `json:"method"`
	Path         string      `json:"path"`
	Headers      any         `json:"headers"`
	Body         interface{} `json:"body"`
	Resonse      interface{} `json:"resonse"`
	Console      []string    `json:"console"`
	Info         map[string]interface{}
}

var logs map[string]logInfo = make(map[string]logInfo)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		splitedRequestId := strings.Split(uuid.New().String(), "-")
		requestId := splitedRequestId[len(splitedRequestId)-1]

		logs[requestId] = logInfo{
			RequestId:  requestId,
			ReqTime:    time.Now().UTC(),
			Info:       map[string]interface{}{},
			Method:     r.Method,
			Path:       r.URL.Path,
			Host:       r.Host,
			Headers:    r.Header,
			StatusCode: 200,
		}

		ctx := context.WithValue(r.Context(), RequestLogKey, requestId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Console(requestId string, value string) {
	copyLog := logs[requestId]
	copyLog.Console = append(logs[requestId].Console, value)
	logs[requestId] = copyLog
}

func AssignLog(requestId string, info map[string]interface{}) {
	copyLog := logs[requestId]
	copyLog.Info = info
	logs[requestId] = copyLog
}

// Set status code
func SetStatusCodeAndMessage(requestId string, statusCode int, message string) {
	copyLog := logs[requestId]
	copyLog.StatusCode = statusCode
	copyLog.ErrorMessage = message
	logs[requestId] = copyLog
}

func PrintLog(requestId string) {
	// Log ingos
	logInfo := logs[requestId]
	headers, _ := common.JsonStringify(logInfo.Headers)

	headers = strings.ReplaceAll(headers, "[", "")
	logInfo.Headers = strings.ReplaceAll(headers, "]", "")
	// Response time
	logInfo.ResTime = time.Now().UTC()
	logInfo.ResTimeSec = printer.Sprintf("%dms", logInfo.ResTime.UnixMilli()-logInfo.ReqTime.UnixMilli())

	fmt.Println(strings.Repeat("-", 50))
	log.Println("("+requestId+") "+logInfo.Method+" | Path:", logInfo.Path+" ("+logInfo.ResTimeSec+") "+strconv.Itoa(logInfo.StatusCode)+" "+logInfo.ErrorMessage)

	// Converted to string
	out, _ := common.JsonStringify(logInfo)
	out = strings.ReplaceAll(out, "\\", "")
	fmt.Println(out)

	delete(logs, requestId) // Delete key
}
