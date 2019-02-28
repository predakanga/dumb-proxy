package proxy

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const asciiLettersSize = len(asciiLetters)

func randomString(length int) string {
	bytes := make([]byte, length)

	for i := range bytes {
		bytes[i] = asciiLetters[rand.Intn(asciiLettersSize)]
	}

	return string(bytes)
}

func pipe(src net.Conn, dst net.Conn, pending *bufio.ReadWriter, direction string) {
	defer src.Close()
	defer dst.Close()

	transferMetric := dataTransferred.WithLabelValues("tunnel", direction)

	if pending != nil {
		pendingWritten, _ := pending.WriteTo(dst)
		transferMetric.Add(float64(pendingWritten))
	}
	written, _ := io.Copy(dst, src)
	transferMetric.Add(float64(written))
}

func defaultHttpError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

func (l LeveledLogger) Printf(fmt string, args ...interface{}) {
	switch l.Level {
	case log.PanicLevel:
		l.Logger.Panicf(fmt, args...)
	case log.FatalLevel:
		l.Logger.Fatalf(fmt, args...)
	case log.ErrorLevel:
		l.Logger.Errorf(fmt, args...)
	case log.WarnLevel:
		l.Logger.Warnf(fmt, args...)
	case log.InfoLevel:
		l.Logger.Warnf(fmt, args...)
	case log.DebugLevel:
		l.Logger.Debugf(fmt, args...)
	default:
		l.Logger.Printf(fmt, args...)
	}
}