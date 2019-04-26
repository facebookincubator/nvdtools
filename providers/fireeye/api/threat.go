package api

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/facebookincubator/nvdtools/providers/fireeye/schema"
)

// FetchAllThreatReportsSince will fetch all vulnerabilities with specified parameters
func (c Client) FetchAllThreatReportsSince(since int64) (<-chan *schema.FireeyeReport, error) {
	parameters := newParametersSince(since)
	if err := parameters.validate(); err != nil {
		return nil, err
	}

	// fetch indexes

	reportIDs := make(chan string)
	wgReportIDs := sync.WaitGroup{}

	for _, params := range parameters.batchBy(ninetyDays) {
		wgReportIDs.Add(1)
		params := params
		go func() {
			defer wgReportIDs.Done()
			log.Printf("Fetching: %s\n", params)
			if rIDs, err := c.fetchReportIDs(params); err == nil {
				for _, rID := range rIDs {
					reportIDs <- rID
				}
			} else {
				log.Println(err)
			}
		}()
	}

	go func() {
		wgReportIDs.Wait()
		close(reportIDs)
	}()

	// fetch reports

	reports := make(chan *schema.FireeyeReport)
	wgReports := sync.WaitGroup{}

	for rID := range reportIDs {
		wgReports.Add(1)
		rID := rID
		go func() {
			defer wgReports.Done()
			if report, err := c.fetchReport(rID); err == nil {
				reports <- report
			} else {
				log.Println(err)
			}
		}()
	}

	go func() {
		wgReports.Wait()
		close(reports)
	}()

	return reports, nil
}

func (c Client) fetchReportIDs(parameters timeRangeParameters) ([]string, error) {
	resp, err := c.Request(fmt.Sprintf("/report/index?intelligenceType=threat&%s", parameters.query()))
	if err != nil {
		return nil, err
	}

	var reportIndex []*schema.FireeyeReportIndexItem
	if err := json.NewDecoder(resp).Decode(&reportIndex); err != nil {
		return nil, err
	}

	reportIDs := make([]string, len(reportIndex))
	for i := 0; i < len(reportIndex); i++ {
		reportIDs[i] = reportIndex[i].ReportID
	}

	return reportIDs, nil
}

func (c Client) fetchReport(reportID string) (*schema.FireeyeReport, error) {
	resp, err := c.Request(fmt.Sprintf("/report/%s?detail=full", reportID))
	if err != nil {
		return nil, err
	}

	var wrapper schema.FireeyeReportWrapper
	if err := json.NewDecoder(resp).Decode(&wrapper); err != nil {
		return nil, err
	}

	return &wrapper.Report, nil
}
