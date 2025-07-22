package logger

import "flag"

// LogBuffEnabled is a flag that sets whether logs will be push into the buffer
var logBuffEnabled = flag.Bool("lbe", true, "lbe - Log Buffer Enabled sets whether logs will be push into the buffer")

// LogBuffSize is a flag that sets the size of the buffer in MB
var logBuffSize = flag.Uint("lbs", 8, "lbs - Log Buffer Size sets the size of the buffer in MB")

// logLevel sets the default log level at the startup
var logLevel = flag.String("llev", "info", "Log LEVel sets log level. Possible values are: debug, info, warn, error, dpanic, panic, fatal")
