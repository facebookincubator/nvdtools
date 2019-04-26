package rate

import (
	"time"
)

// Limiter provides only one function: Allow. it blocks until routine can proceed
type Limiter interface {
	Allow()
}

type token struct{}

type limiter struct {
	tokens chan token
}

// BurstyLimiter will create a limiter which allows bursts of maximum requestsPerPeriod
// and otherwise allows requests with period/requestsPerPeriod gap in between
func BurstyLimiter(period time.Duration, requestsPerPeriod int) Limiter {
	l := &limiter{
		tokens: make(chan token, requestsPerPeriod),
	}

	// start filling indefinitely
	go func() {
		for range time.Tick(period / time.Duration(requestsPerPeriod)) {
			l.tokens <- token{}
		}
	}()

	return l
}

func (l *limiter) Allow() {
	<-l.tokens
}
