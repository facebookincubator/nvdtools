package schema

// FlexeraAdvisoryListResult type
type FlexeraAdvisoryListResult struct {
	Count   int                           `json:"count"`
	Next    string                        `json:"next"`
	Previus string                        `json:"previous"`
	Results []*FlexeraAdvisoryListElement `json:"results"`
}

// FlexeraAdvisoryListElement type
type FlexeraAdvisoryListElement struct {
	ID                 int64  `json:"id"`
	AdvisoryIdentifier string `json:"advisory_identifier"`
	Released           string `json:"released"`
	Modified           string `json:"modified_date"`
	// rest we don't need, it's included in the detail
}
