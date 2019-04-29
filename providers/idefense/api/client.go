package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/facebookincubator/nvdtools/providers/idefense/schema"
	"github.com/pkg/errors"
)

// Client struct
type Client struct {
	APIKey string
	URL    url.URL
}

const (
	pageSize  = 200
	userAgent = "fb-idefense"
)

// NewClient creates an object which is used to query the iDefense API
func NewClient(u, apiKey string, parameters map[string]interface{}) Client {
	apiURL, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	apiURL.RawQuery = createQuery(parameters).Encode()

	return Client{
		APIKey: apiKey,
		URL:    *apiURL,
	}
}

func createQuery(parameters map[string]interface{}) *url.Values {
	query := url.Values{}
	for key, value := range parameters {
		log.Printf("querying with %s = %v\n", key, value)
		switch v := value.(type) {
		case string:
			query.Add(key, v)
		case []string:
			for _, s := range v {
				query.Add(key, s)
			}
		case int:
			query.Add(key, strconv.Itoa(v))
		case bool:
			query.Add(key, strconv.FormatBool(v))
		}
	}
	return &query
}

// FetchAll will fetch all vulnerabilities from iDefense API
func (client Client) FetchAll() (<-chan *schema.IDefenseVulnerability, error) {
	result, err := client.query(map[string]string{"page_size": "0"})
	if err != nil {
		return nil, err
	}

	totalVulns := result.TotalSize
	if totalVulns == 0 {
		return nil, errors.New("no vulnerabilities found in given window")
	}

	output := make(chan *schema.IDefenseVulnerability)
	numPages := (totalVulns-1)/pageSize + 1

	// fetch pages concurrently
	log.Printf("starting sync for %d vulnerabilities over %d pages\n", totalVulns, numPages)
	wg := sync.WaitGroup{}
	for page := 1; page <= numPages; page++ {
		wg.Add(1)
		go func(p int) {
			if err := client.fetchPage(p, output); err != nil {
				log.Println(err)
			}
			wg.Done()
		}(page)
	}

	go func() {
		wg.Wait()
		close(output)
	}()

	return output, nil
}

func (client Client) fetchPage(page int, output chan<- *schema.IDefenseVulnerability) error {
	result, err := client.query(map[string]string{
		"page":      strconv.Itoa(page),
		"page_size": strconv.Itoa(pageSize),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to get page %d", page)
	}
	for _, vuln := range result.Results {
		if vuln != nil {
			output <- vuln
		}
	}
	return nil
}

func (client Client) query(params map[string]string) (*schema.IDefenseVulnerabilitySearchResults, error) {
	// setup new parameters
	u, err := url.Parse(client.URL.String()) // in other words: url.copy()
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse client URL")
	}
	query := u.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	u.RawQuery = query.Encode()

	resp, err := queryURL(u.String(), http.Header{
		"Auth-Token": {client.APIKey},
		"User-Agent": {userAgent},
	})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// decode into json
	var result schema.IDefenseVulnerabilitySearchResults
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}

	return &result, nil
}
