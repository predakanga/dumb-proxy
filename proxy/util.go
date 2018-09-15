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

func pipe(src net.Conn, dst net.Conn, pending *bufio.ReadWriter) {
	defer src.Close()
	defer dst.Close()

	if pending != nil {
		pending.WriteTo(dst)
	}
	io.Copy(dst, src)
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