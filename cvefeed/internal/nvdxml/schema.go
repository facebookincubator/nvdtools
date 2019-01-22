// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvdxml

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/jokLiu/nvdtools/cvefeed/internal/iface"
	"github.com/jokLiu/nvdtools/wfn"
)

// TextType represents multi-language text
type TextType map[string]string

// UnmarshalXML -- load TextType from XML
func (t *TextType) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var text string
	lang := "en"
	if *t == nil {
		*t = TextType{}
	}
	for _, attr := range start.Attr {
		if attr.Name.Local == "lang" {
			lang = attr.Value
		}
	}
	if err := d.DecodeElement(&text, &start); err != nil {
		return err
	}
	(*t)[lang] = text
	return nil
}

// PlatformType -- NVD doesn't use it
// TODO: implement
// type PlatformType struct{}

// CheckFactRefType is a reference to a check that always evaluates to
// TRUE, FALSE, or ERROR. Examples of types of checks are OVAL and OCIL checks.
// NVD doesn't use it
// TODO: implement
// type CheckFactRefType struct{}

// NamePattern represents CPE name
type NamePattern wfn.Attributes

// UnmarshalXMLAttr implements xml.UnmarshalerAttr interface
func (np *NamePattern) UnmarshalXMLAttr(attr xml.Attr) error {
	wfn, err := wfn.Parse(attr.Value)
	if err != nil {
		return err
	}
	*np = (NamePattern)(*wfn)
	return nil
}

func (np NamePattern) String() string {
	return wfn.Attributes(np).String()
}

// FactRefType is a reference to a CPE Name that always evaluates to a Boolean result
type FactRefType struct {
	Name        NamePattern `xml:"name,attr"`
	Description string      `xml:"description,attr"`
}

// OperatorString defines acceptable operators
type OperatorString string

// UnmarshalXMLAttr -- load OperatorString from XML
func (t *OperatorString) UnmarshalXMLAttr(attr xml.Attr) error {
	switch v := strings.ToLower(attr.Value); v {
	case "and", "or":
		*t = OperatorString(v)
	default:
		return fmt.Errorf("undefined value %q in OperatorString", attr.Value)
	}
	return nil
}

func (t *OperatorString) String() string {
	return string(*t)
}

// LogicalTestType defines test using logical operators (AND, OR, negate).
type LogicalTestType struct {
	Op                OperatorString      `xml:"operator,attr"`
	Neg               bool                `xml:"negate,attr"`
	LogicalTests      []*LogicalTestType  `xml:"logical-test"`
	ifaceLogicalTests []iface.LogicalTest // for re-parsing LogicalTests as []iface.LogicalTest interfaces
	FactRefs          []*FactRefType      `xml:"fact-ref"`
	//TODO: CheckFactRefs []CheckFactRefType   `xml:"check-fact-ref"`
}

func (t *LogicalTestType) String() string {
	var parts []string
	for _, lt := range t.LogicalTests {
		parts = append(parts, "("+lt.String()+")")
	}
	for _, fr := range t.FactRefs {
		parts = append(parts, fmt.Sprintf("%+v", fr))
	}
	return strings.Join(parts, " "+t.Op.String()+" ")
}

// PlatformBaseType represents the description or qualifications of a particular IT platform type.
// The platform is defined by the logical-test child element.
type PlatformBaseType struct {
	Title       TextType         `xml:"title"`
	Remark      TextType         `xml:"remark"`
	LogicalTest *LogicalTestType `xml:"cpe-logical-test"`
}

// PlatformSpecificationType is the root element of a CPE Applicability Language
// XML document and therefore acts as a container for child platform definitions.
type PlatformSpecificationType struct {
	PlatformConfiguration *PlatformBaseType `xml:"platform-configuration"`
	LogicalTest           *LogicalTestType  `xml:"logical-test"`
	FactRef               *FactRefType      `xml:"fact-ref"`
	// Platform              *PlatformType     `xml:"platform"`
	// CheckFactRef          *CheckFactRefType `xml:"check-fact-ref"`
}

// Entry represents a CVE entry
type Entry struct {
	ID            string                       `xml:"id,attr"`
	Configuration []*PlatformSpecificationType `xml:"vulnerable-configuration"`
	ifaceConfig   []iface.LogicalTest          // for reparsing Config field as []iface.LogicalTest
	CVE           string                       `xml:"cve-id"`
}

// NVDFeed represents the root element of NVD CVE feed
type NVDFeed struct {
	Entries       []*Entry `xml:"entry"`
	NVDXMLVersion string   `xml:"nvd_xml_version,attr"`
	PubDate       string   `xml:"pub_date,attr"`
}
