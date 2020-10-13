package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

type Log struct {
	Tag     string `json:"tag"`
	Message string `json:"message"`
}

// Get environment variable, if it is not found return default value
func getEnv(key string, defvalue string) string {
	value := os.Getenv(key)

	if len(value) <= 0 {
		value = defvalue
	}

	return value
}

func getAddr(port string) string {
	return fmt.Sprintf(":%v", port)
}

func main() {
	log.Print("Logger started")

	http.HandleFunc("/info", LogHadler)
	http.HandleFunc("/error", LogHadler)
	http.HandleFunc("/warning", LogHadler)

	addr := getAddr(getEnv("LOGGER_PORT", "8082"))

	log.Printf("Log server listening on %v", addr)

	http.ListenAndServe(addr, nil)
}

func LogHadler(w http.ResponseWriter, r *http.Request) {
	var logLevel string

	switch r.URL.Path {
	case "/info":
		logLevel = "INFO"
	case "/error":
		logLevel = "ERROR"
	case "/warning":
		logLevel = "WARNING"
	default:
		logLevel = "INFO"
	}

	switch r.Method {
	case "POST":
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}

		var log Log

		json.Unmarshal(reqBody, &log)

		fmt.Printf("%s %s %s:%s\n",
			time.Now().Format("2006/01/02 15:04:05"),
			logLevel,
			log.Tag,
			log.Message)

		w.Write([]byte("Received Log request\n"))
	default:
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
	}
}
