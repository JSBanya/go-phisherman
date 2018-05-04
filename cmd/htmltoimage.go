package main

import (
	"bytes"
	"github.com/anthonynsimon/bild/effect"
	"github.com/anthonynsimon/bild/transform"
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
func getImageFromURL(url string) ([]byte, error) {
	cmd := exec.Command("wkhtmltoimage", "-q", "--height", "1080", "-f", "jpeg", url, "/dev/stdout")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return out.Bytes(), err
}

func getPageHead(raw []byte) ([]byte, error) {
	imageReader := bytes.NewReader(raw)
	original, _, err := image.Decode(imageReader)
	if err != nil {
		return []byte{}, err
	}

	bounds := original.Bounds()
	result := transform.Crop(original, image.Rect(0, 0, bounds.Dx(), 100))

	buf := new(bytes.Buffer)
	err = jpeg.Encode(buf, result, nil)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// Returns a image containing only edges
func getImageEdges(raw []byte) ([]byte, error) {
	imageReader := bytes.NewReader(raw)
	original, _, err := image.Decode(imageReader)
	if err != nil {
		return []byte{}, err
	}

	result := effect.EdgeDetection(effect.Grayscale(original), 4.0)
	buf := new(bytes.Buffer)
	err = jpeg.Encode(buf, result, nil)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

// Takes the given image binary data and converts to 8-bit image array
// Returns the array and the width of the image
func imageToPixels(raw []byte) ([]byte, error) {
	imageReader := bytes.NewReader(raw)
	img, _, err := image.Decode(imageReader)
	if err != nil {
		return []byte{}, err
	}

	bounds := img.Bounds()
	pixels := []byte{}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			pixels = append(pixels, colorToByte(r))
			pixels = append(pixels, colorToByte(g))
			pixels = append(pixels, colorToByte(b))
		}
	}

	return pixels, nil
}

func colorToByte(col uint32) byte {
	unmodded := byte(col / 0x101)
	mod := byte(unmodded % 10)
	newCol := unmodded - mod
	if newCol == 0 {
		return 1
	}

	return newCol
}
