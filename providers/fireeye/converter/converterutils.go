package converter

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
	"github.com/facebookincubator/nvdtools/providers/fireeye/schema"
)

func extractCVSSBaseScore(item *schema.FireeyeVulnerability) float64 {
	return strToFloat(item.CvssBaseScore)
}

func extractCVSSTemporalScore(item *schema.FireeyeVulnerability) float64 {
	return strToFloat(item.CvssTemporalScore)
}

func extractCVSSVectorString(item *schema.FireeyeVulnerability) string {
	return strings.Trim(item.CvssBaseVector, "()")
}

func extractCPEs(item *schema.FireeyeVulnerability) []string {
	return strings.Split(item.CPE, ",")
}

func convertTime(fireeyeTime int64) string {
	return time.Unix(fireeyeTime, 0).Format(nvdcommon.TimeLayout)
}

func strToFloat(str string) float64 {
	f, err := strconv.ParseFloat(str, 64)
	if err != nil {
		log.Println(err)
		f = float64(0)
	}
	return f
}
