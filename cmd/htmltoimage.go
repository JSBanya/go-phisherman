package main

import (
	"bytes"
	"github.com/anthonynsimon/bild/effect"
	"image"
	"image/jpeg"
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

// Returns a image containing only edges
func getImageEdges(raw []byte) ([]byte, error) {
	imageReader := bytes.NewReader(raw)
	original, _, err := image.Decode(imageReader)
	if err != nil {
		return []byte{}, err
	}

	result := effect.EdgeDetection(original, 1.0)
	buf := new(bytes.Buffer)
	err = jpeg.Encode(buf, result, nil)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}
