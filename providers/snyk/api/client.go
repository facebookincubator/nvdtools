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

package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/facebookincubator/nvdtools/providers/lib/download"
)

type Client struct {
	consumerID string
	secret     string
	userAgent  string
}

func NewClient(consumerID, secret, userAgent string) Client {
	return Client{
		consumerID: consumerID,
		secret:     secret,
		userAgent:  userAgent,
	}
}

func (c Client) Get(url string) (io.ReadCloser, error) {
	tok, err := c.createToken()
	if err != nil {
		return nil, fmt.Errorf("cannot create jwt token: %v", err)
	}

	resp, err := download.Get(url, http.Header{
		"User-Agent":    {c.userAgent},
		"Authorization": {"Bearer" + tok},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get response from %s: %v", url, err)
	}

	return resp.Body, nil
}

func (c *Client) createToken() (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Issuer:   c.consumerID,
		IssuedAt: time.Now().Unix(),
	})
	return tok.SignedString([]byte(c.secret))
}
