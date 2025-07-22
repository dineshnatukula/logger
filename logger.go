package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/metadata"
)

var pid = os.Getpid()
var serviceName = path.Base(os.Args[0])

const (
	// DebugLevel logs are typically voluminous, and are usually disabled in
	// production.
	DebugLevel = zapcore.DebugLevel
	// InfoLevel is the default logging priority.
	InfoLevel = zapcore.InfoLevel
	// WarnLevel logs are more important than Info, but don't need individual
	// human review.
	WarnLevel = zapcore.WarnLevel
	// ErrorLevel logs are high-priority. If an application is running smoothly,
	// it shouldn't generate any error-level logs.
	ErrorLevel = zapcore.ErrorLevel
	// DPanicLevel logs are particularly important errors. In development the
	// logger panics after writing the message.
	DPanicLevel = zapcore.DPanicLevel
	// PanicLevel logs a message, then panics.
	PanicLevel = zapcore.PanicLevel
	// FatalLevel logs a message, then calls os.Exit(1).
	FatalLevel = zapcore.FatalLevel
)

const (
	// XRequestIDKey is a key for getting request id.
	XRequestIDKey = "X-Request-ID"
	UserSession   = "user-session"
	PlayerId      = "player-id"
	BrandId       = "X-Brand"
)

var tracingFields = []string{UserSession, PlayerId, XRequestIDKey, BrandId}

// Logger is a logger structure
type Logger struct {
	Z *zap.Logger
	*zap.Config
}

// L is a global logger with default configuration
var L *Logger
var initialized bool

var defaultLoggerConfig = zap.Config{
	Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
	DisableCaller:     true,
	DisableStacktrace: true,
	Encoding:          "console",
	EncoderConfig: zapcore.EncoderConfig{
		LevelKey:       "level",
		TimeKey:        "created",
		NameKey:        "name",
		CallerKey:      "caller",
		StacktraceKey:  "trace",
		MessageKey:     "msg",
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    CustomLevelEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	},
	InitialFields: map[string]interface{}{
		"Service": serviceName,
		//		"PID":     pid, // moved to initDefaultLogger()
	},
	OutputPaths:      []string{"stdout"},
	ErrorOutputPaths: []string{"stderr"},
}

// CustomLevelEncoder writes [LEVEL]
func CustomLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + level.CapitalString() + "]")
}

var onceInit = &sync.Once{}

// Init initializes global logger with the default configuration.
// Default logger has buffer with deafult size of 8MB that can be set
// through flag parameters -lsb and -lse. Default log level is 'info' and
// it could be changed with -llev flag param.
// Default Logger can be initialized just once, if there is a need for additional logger,
// it can be done through NewCustomLogger func
func Init() {
	onceInit.Do(func() {
		L = initDefaultLogger()
		initialized = true
		L.Info("logging started", zap.String("level", L.Level.String()))
	},
	)
}

// initDefaultLogger creates logger with the default configuration, and creates buffer as set in flags
func initDefaultLogger() *Logger {

	c := &defaultLoggerConfig

	if *logBuffEnabled && *logBuffSize > uint(0) {
		sink = newMemorySink(*logBuffSize)
		zap.RegisterSink("memory", func(*url.URL) (zap.Sink, error) {
			return sink, nil
		})
		c.OutputPaths = append(c.OutputPaths, "memory://")
	}

	if *logLevel != flag.Lookup("llev").DefValue {
		al := zap.NewAtomicLevel()
		err := al.UnmarshalText([]byte(*logLevel))
		if err != nil {
			panic(err)
		}

		c.Level.SetLevel(al.Level())
	}
	//
	// $HOSTNAME keeps the name of the service and PodId. For example HOSTNAME=autocashouthandlerd-664d7c7589-pc8jg
	// If there are no three parts of the $HOSTNAME separated by "-", lets assume that service is running on a local machine and put PID in logs.
	// Use the second and third part as PodId, instead
	//
	hostname := os.Getenv("HOSTNAME")
	parts := strings.Split(hostname, "-")
	if len(parts) != 3 {
		c.InitialFields["PID"] = pid
	} else {
		c.InitialFields["Pod"] = parts[1] + "-" + parts[2]
	}
	//
	lg, err := NewCustomLogger(c)
	if err != nil {
		panic(err)
	}

	return lg
}

// NewCustomLogger creates logger with custom configuration
func NewCustomLogger(config *zap.Config) (*Logger, error) {

	lg := &Logger{}

	if config == nil {
		lg.Config = &defaultLoggerConfig
	} else {
		lg.Config = config
	}

	l, err := lg.Config.Build()
	if err != nil {
		return nil, err
	}

	lg.Z = l

	return lg, nil
}

// WithRequestID returns logger with inserted field ReqID
func (l *Logger) WithRequestID(ctx context.Context) *zap.Logger {
	if ctx != nil {
		//l.Z = l.Z.With(zap.String("ReqID", ReqIDFromContext(ctx)))

		return l.Z.With(zap.String("RequestID", ReqIDFromContext(ctx)))
	}
	return l.Z
}

// LogDuration logs duration of a function
func (l *Logger) LogDuration(ctx context.Context, startTime time.Time, fields ...zapcore.Field) {

	if l.Level.Level() > zapcore.InfoLevel {
		return
	}

	callerF := func() string {
		fpcs := make([]uintptr, 1)

		n := runtime.Callers(3, fpcs)
		if n == 0 {
			// no caller
			return ""
		}

		caller := runtime.FuncForPC(fpcs[0] - 1)
		if caller == nil {
			// caller was nil
			return ""
		}
		return caller.Name()
	}

	f := []zapcore.Field{
		zap.String("Function", callerF()),
		zap.Time("Start", startTime),
		zap.Duration("Seconds", time.Since(startTime))}

	if len(fields) > 0 {
		f = append(f, fields...)
	}

	if ctx != nil {
		l.WithRequestID(ctx).Info("F duration", f...)
		return
	}
	l.Info("F duration", f...)
}

// Info logs at Info level
func (l *Logger) Info(msg string, fields ...zap.Field) {
	if !initialized {
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Info(msg, fields...)
}

func (l *Logger) InfoWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Info(msg, fields...)
}

// Info logs at Info level
func Info(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[INFO]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Info(msg, fields...)
}

func InfoWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[INFO]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Info(msg, fields...)
}

// Warn logs at Warn level
func (l *Logger) Warn(msg string, fields ...zap.Field) {
	if !initialized {
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Warn(msg, fields...)
}

func (l *Logger) WarnWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Warn(msg, fields...)
}

// Warn logs at Warn level
func Warn(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[WARN]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Warn(msg, fields...)
}

func WarnWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[WARN]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Warn(msg, fields...)
}

// Debug logs at Debug level
func (l *Logger) Debug(msg string, fields ...zap.Field) {
	if !initialized {
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Debug(msg, fields...)
}

func (l *Logger) DebugWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Debug(msg, fields...)
}

// Debug logs at Debug level
func Debug(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[DEBUG]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Debug(msg, fields...)
}

func DebugWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[DEBUG]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Debug(msg, fields...)
}

// Error logs at Error level
func (l *Logger) Error(msg string, fields ...zap.Field) {
	if !initialized {
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Error(msg, fields...)
}

func (l *Logger) ErrorWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Error(msg, fields...)
}

// LogError logs at Error level
func LogError(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[ERROR]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Error(msg, fields...)
}

func LogErrorWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[ERROR]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Error(msg, fields...)
}

// DPanic logs at DebugPanic level
func (l *Logger) DPanic(msg string, fields ...zap.Field) {
	if !initialized {
		panic(fmt.Sprint(msg, fields))
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.DPanic(msg, fields...)
}

func (l *Logger) DPanicWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		panic(fmt.Sprint(msg, fields))
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.DPanic(msg, fields...)
}

// DPanic logs at DebugPanic level
func DPanic(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[DPANIC]\t%s\t%v\n", NowStr(), msg, fields)
		panic(fmt.Sprint(msg, fields))
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.DPanic(msg, fields...)
}

func DPanicWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[DPANIC]\t%s\t%v\n", NowStr(), msg, fields)
		panic(fmt.Sprint(msg, fields))
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.DPanic(msg, fields...)
}

// Panic logs at Panic level
func (l *Logger) Panic(msg string, fields ...zap.Field) {
	if !initialized {
		panic(fmt.Sprint(msg, fields))
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Panic(msg, fields...)
}

func (l *Logger) PanicWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		panic(fmt.Sprint(msg, fields))
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Panic(msg, fields...)
}

// Panic logs at Panic level
func Panic(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[PANIC]\t%s\t%v\n", NowStr(), msg, fields)
		panic(fmt.Sprint(msg, fields))
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Panic(msg, fields...)
}

func PanicWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[PANIC]\t%s\t%v\n", NowStr(), msg, fields)
		panic(fmt.Sprint(msg, fields))
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Panic(msg, fields...)
}

// Fatal logs at Fatal level
func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	if !initialized {
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Fatal(msg, fields...)
}

func (l *Logger) FatalWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	l.Z.Fatal(msg, fields...)
}

// Fatal logs at Fatal level
func Fatal(msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[FATAL]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}
	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Fatal(msg, fields...)
}

func FatalWithContext(ctx context.Context, msg string, fields ...zap.Field) {
	if !initialized {
		fmt.Printf("%s\t[FATAL]\t%s\t%v\n", NowStr(), msg, fields)
		return
	}

	ctxField := getTraceIds(ctx)
	fields = append(ctxField, fields...)

	msg = fmt.Sprintf("\"%s\"", msg)
	L.Z.Fatal(msg, fields...)
}

// Sync syncs (flushes) the log buffer
func (l *Logger) Sync() error {
	if !initialized {
		return nil
	}
	return l.Z.Sync()
}

// WriteBufferTo writes Sink buffer data to provided writer w.
// If sink is not initialized, error will be returned.
func (l *Logger) WriteBufferTo(w io.Writer) error {
	if sink == nil {
		return errors.New("log buffer sink is not initialized")
	}

	return sink.writeCopyTo(w)
}

//Print calls Logger.Info with fmt.Sprint as argument
func (l *Logger) Print(v ...interface{}) {
	s := fmt.Sprint(v...)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	l.Info(s)
}

//Println calls Logger.Info with fmt.Sprintln as argument
func (l *Logger) Println(v ...interface{}) {
	//l.Info(fmt.Sprintln(v...))
	l.Print(v...)
}

//Printf calls Logger.Info with fmt.Sprintf as argument
func (l *Logger) Printf(format string, v ...interface{}) {
	l.Info(fmt.Sprintf(strings.TrimRight(format, "\n"), v...))
	//l.Info(fmt.Sprintf(format, v...))
	// s := fmt.Sprint(v...)
	// if s[len(s)-1] == '\n' {
	// 	s = s[:len(s)-1]
	// }
	// l.Info(s)
}

// request ID
type requestIDKey string

// ContextKey ...
//var ContextKey = requestIDKey("reqid")
var ContextKey = requestIDKey("X-Request-ID")

// ReqIDFromContext request key from context
func ReqIDFromContext(ctx context.Context) string {

	if v := ctx.Value(ContextKey); v != nil {
		str := fmt.Sprintf("%v", v)
		return str
	}
	return ""
}

func getTraceIds(ctx context.Context) []zap.Field {
	var fields []zap.Field

	if ctx == nil {
		return fields
	}

	for _, field := range tracingFields {
		v := ctx.Value(field)
		if v == nil {
			continue
		}

		val := fmt.Sprintf("%v", v)
		fields = append(fields, String(field, val))
	}

	return fields
}

// GetContextWithReqID returns context with requestID
func GetContextWithReqID(ctx context.Context) context.Context {
	requestID := xid.New()
	ctx = context.WithValue(ctx, ContextKey, requestID)
	return ctx
}

// GetContextWithReqIDFromHeader returns context with requestID
func GetContextWithReqIDFromHeader(ctx context.Context, req *http.Request) context.Context {
	requestID := req.Header.Get(XRequestIDKey)
	if requestID == "" {
		requestID = xid.New().String()
	}
	ctx = context.WithValue(ctx, ContextKey, requestID)
	return ctx
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and log the request body
		body, err := ioutil.ReadAll(r.Body)

		requestID := r.Header.Get(XRequestIDKey)
		if requestID == "" {
			requestID = xid.New().String()
		}
		userSession := r.Header.Get(UserSession)
		playerId := r.Header.Get(PlayerId)
		brandId := r.Header.Get(BrandId)

		// Log the request
		L.Info("HTTP Request", String(UserSession, userSession), String(PlayerId, playerId),
			String(XRequestIDKey, requestID), String(BrandId, brandId), String("Method", r.Method),
			String("Path", r.URL.Path), Json("RequestBody", body), Error(err))

		// Restore the request body for downstream handlers
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		// Measure the execution time
		start := time.Now()

		// Create a response writer wrapper to capture the response status code and body
		rw := &responseWriter{ResponseWriter: w, responseBody: bytes.NewBuffer(nil)}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Calculate the execution time
		elapsed := time.Since(start)

		// Read and log the response body
		responseBody := rw.responseBody.Bytes()

		// Log response
		L.Info("HTTP Response", String(UserSession, userSession), String(PlayerId, playerId),
			String(XRequestIDKey, requestID), String(BrandId, brandId), String("Method", r.Method),
			String("Path", r.URL.Path), Error(err), Int("StatusCode", rw.statusCode),
			String("StatusText", http.StatusText(rw.statusCode)),
			Json("ResponseBody", responseBody), Any("Elapsed", elapsed))
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	responseBody *bytes.Buffer
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	rw.responseBody.Write(data)
	return rw.ResponseWriter.Write(data)
}

func GetContextWithTracingFieldsFromHeader(req *http.Request) context.Context {
	requestID := req.Header.Get(XRequestIDKey)
	if requestID == "" {
		requestID = xid.New().String()
	}
	userSession := req.Header.Get(UserSession)
	playerId := req.Header.Get(PlayerId)
	brandId := req.Header.Get(BrandId)

	ctx := req.Context()
	ctx = context.WithValue(ctx, XRequestIDKey, requestID)
	ctx = context.WithValue(ctx, UserSession, userSession)
	ctx = context.WithValue(ctx, PlayerId, playerId)
	ctx = context.WithValue(ctx, BrandId, brandId)

	return ctx
}

// RequestIDAnnotator takes requestID from http request header and sets it to metadata.
func RequestIDAnnotator(ctx context.Context, req *http.Request) metadata.MD {
	requestID := req.Header.Get(XRequestIDKey)
	if requestID == "" {
		requestID = xid.New().String()
	}

	return metadata.New(map[string]string{
		XRequestIDKey: requestID,
	})
}

//LogLevel GET/PUT loglevel
func LogLevel(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	L.Config.Level.ServeHTTP(w, r)
}

// SetLevel sets logging level of L
func SetLevel(level string) error {
	if !initialized {
		return nil
	}

	err := L.Config.Level.UnmarshalText([]byte(level))
	if err != nil {
		L.Error("logger.SetLevel", String("level", level), Error(err))
		return err
	}

	L.Warn("logger.SetLevel changed", String("new level", level))
	return nil
}

//GetLog returns log buffer
func GetLog(w http.ResponseWriter, r *http.Request) {
	err := L.WriteBufferTo(w)
	if err != nil {
		L.Error("Log handler", zap.Error(err))
	}
}

//GetLog returns log buffer
func (l *Logger) GetLog(w http.ResponseWriter, r *http.Request) {
	err := l.WriteBufferTo(w)
	if err != nil {
		l.Error("Log handler", zap.Error(err))
	}
}

// Bool accepts bool
func Bool(key string, val bool) zap.Field {
	return zap.Bool(key, val)
}

// String accepts a string
func String(key, val string) zap.Field {
	return zap.String(key, val)
}

// Strings accepts a string slice
func Strings(key string, val []string) zap.Field {
	return zap.Strings(key, val)
}

// ByteString accepts []byte and prints it as string
func ByteString(key string, val []byte) zap.Field {
	return zap.ByteString(key, val)
}

// Error accepts an error
func Error(err error) zap.Field {
	return zap.Error(err)
}

// ErrorMsg accepts an error with title
func ErrorMsg(key string, err error) zap.Field {
	return zap.String(key, err.Error())
}

// Int accepts an int
func Int(key string, val int) zap.Field {
	return zap.Int(key, val)
}

// Ints accepts an int slice
func Ints(key string, val []int) zap.Field {
	return zap.Ints(key, val)
}

// Int64 accepts an int64
func Int64(key string, val int64) zap.Field {
	return zap.Int64(key, val)
}

// Int32 accepts an int32
func Int32(key string, val int32) zap.Field {
	return zap.Int32(key, val)
}

// Uint accepts an uint
func Uint(key string, val uint) zap.Field {
	return zap.Uint(key, val)
}

// Uint64 accepts an uint64
func Uint64(key string, val uint64) zap.Field {
	return zap.Uint64(key, val)
}

// Time accepts time.Time
func Time(key string, val time.Time) zap.Field {
	return zap.Time(key, val)
}

// Duration accepts duration
func Duration(key string, val time.Duration) zap.Field {
	return zap.Duration(key, val)
}

// Reflect accepts anything
func Reflect(key string, val interface{}) zap.Field {
	return zap.Reflect(key, val)
}

// Any old music will do...
func Any(key string, val interface{}) zap.Field {
	return zap.Any(key, val)
}

// Json accepts val []byte in JSON format, and puts it in the log properly.
// val must be valid json string (in the form of []byte).
func Json(key string, val []byte) zap.Field {
	r := json.RawMessage(val)
	return zap.Any(key, &r)
}

// Float64 constructs a field that carries a float64
func Float64(key string, val float64) zap.Field {
	return zap.Float64(key, val)
}

// Float32 constructs a field that carries a float64
func Float32(key string, val float32) zap.Field {
	return zap.Float32(key, val)
}

// NowStr returns string containing current time in UTC
func NowStr() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// init creates logger with minimum configuration, no buffer
func init() {
	var err error

	c := &defaultLoggerConfig

	L, err = NewCustomLogger(c)
	if err != nil {
		panic(err)
	}
}
