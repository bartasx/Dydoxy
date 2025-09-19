package logging

import (
	"github.com/sirupsen/logrus"
)

func NewLogger(level string) *logrus.Logger {
	logger := logrus.New()
	
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	
	logger.SetLevel(logLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})
	
	return logger
}