package converter

import (
	"log"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
)

var snykLayouts = []string{
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05.000000Z",
}

func snykTimeToNVD(s string) string {
	var t time.Time
	var err error

	for _, layout := range snykLayouts {
		t, err = time.Parse(layout, s)
		if err == nil {
			return t.Format(nvdcommon.TimeLayout)
		}
	}

	log.Printf("cannot parse snyk time: %v", err)
	return s
}
