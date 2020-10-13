package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Get environment variable, if it is not found return default value
func getEnv(key string, defvalue string) string {
	value := os.Getenv(key)

	if len(value) <= 0 {
		value = defvalue
	}

	return value
}

func logMessage(path string, tag string, message string) {
	body, err := json.Marshal(map[string]string{
		"tag":     tag,
		"message": message,
	})

	if err != nil {
		fmt.Print(err, "\n")
		return
	}

	serverUrl := getEnv("LOG_SERVER", "http://localhost")
	serverPort := getEnv("LOG_PORT", "8082")
	url := fmt.Sprintf("%s:%s/%s", serverUrl, serverPort, path)

	resp, err := http.Post(
		url,
		"application/json",
		bytes.NewBuffer(body))

	if err != nil {
		fmt.Print(err, "\n")
		return
	}

	fmt.Print(resp.Status)
}

func logInfo(tag string, message string) {
	logMessage("info", tag, message)
}

func logWarning(tag string, message string) {
	logMessage("warning", tag, message)
}

func logError(tag string, message string) {
	logMessage("error", tag, message)
}

func main() {
	// logInfo("SCLOGGER", "Information message")
	// logWarning("SCLOGGER", "Warning message")
	// logError("SCLOGGER", "Error message")

	done := make(chan bool)
	go forever()
	<-done // Block forever
}

func forever() {
	for {
		logInfo(
			"SCLOGGER",
			fmt.Sprintf("Time is %v", time.Now()))
		time.Sleep(time.Second * 10)
	}
}
