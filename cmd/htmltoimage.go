package main

import (
	"bytes"
	"os/exec"
	"strings"
)

// Return the version number of wkhtmltoimage
func getWkHtmlToImageVersion() (string, error) {
	vbytes, err := exec.Command("wkhtmltoimage", "-V").CombinedOutput()
	version := strings.TrimSpace(strings.Replace(string(vbytes), "wkhtmltoimage", "", -1))
	return version, err
}

// Fetches the image of the webpage from the given url
// We use a jpeg format rather than png to minimize the output size of the image to reduce latency
func getImageFromUrl(url string) ([]byte, error) {
	cmd := exec.Command("wkhtmltoimage", "-q", "-f", "jpeg", url, "/dev/stdout")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}
