package converter

import (
	"regexp"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cvefeed/nvdcommon"
	"github.com/facebookincubator/nvdtools/providers/flexera/schema"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/pkg/errors"
)

var (
	// we try to use this to extract name and version from their product
	productRegex = *regexp.MustCompile(`^(.+)\s+([0-9.x]+)$`)
)

func findCPEs(product *schema.FlexeraProduct) ([]string, error) {
	if product.HasCpe {
		var cpes []string
		for _, cpe := range product.Cpes {
			cpes = append(cpes, cpe.Name)
		}
		return cpes, nil
	}

	name, version, err := extractNameAndVersion(product.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to extract product and version from: %s", product.Name)
	}

	part := "a"
	if product.IsOS {
		part = "o"
	}

	attrs, err := createAttributes(part, name, version)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create attributes from: %s, %s, %s", part, name, version)
	}
	attrs.Version = strings.Replace(attrs.Version, "x", "*", 1) // 7\.x -> 7\.*

	return []string{attrs.BindToURI()}, nil
}

func convertTime(flexeraTime string) (string, error) {
	t, err := time.Parse("2006-01-02T15:04:05Z", flexeraTime)
	if err != nil { // should be parsable
		return "", err
	}
	return t.Format(nvdcommon.TimeLayout), nil
}

func extractNameAndVersion(product string) (name, version string, err error) {
	if match := productRegex.FindStringSubmatch(product); match != nil {
		return match[1], match[2], nil
	}
	return "", "", errors.New("Couldn't extract name and version using regex")
}

func createAttributes(part, product, version string) (*wfn.Attributes, error) {
	var err error
	if part, err = wfn.WFNize(part); err != nil {
		return nil, errors.Wrapf(err, "failed to wfnize part: %s", part)
	}
	if product, err = wfn.WFNize(product); err != nil {
		return nil, errors.Wrapf(err, "failed to wfnize product: %s", product)
	}
	if version, err = wfn.WFNize(version); err != nil {
		return nil, errors.Wrapf(err, "failed to wfnize version: %s", version)
	}

	v := wfn.Attributes{
		Part:    part,
		Product: product,
		Version: version,
	}

	return &v, nil
}
