package runner

import (
	"sync"

	"github.com/sametsazak/mergen-cli/internal/checks"
)

// Progress is sent on the channel as each check completes.
type Progress struct {
	Result checks.CheckResult
	Done   int
	Total  int
}

// Run executes all provided checks concurrently (up to workers goroutines)
// and streams Progress updates on the returned channel.
// The channel is closed when all checks are complete.
func Run(cs []checks.Check, workers int) <-chan Progress {
	if workers <= 0 {
		workers = 8
	}

	ch := make(chan Progress, len(cs))
	jobs := make(chan checks.Check, len(cs))
	total := len(cs)

	var (
		mu   sync.Mutex
		done int
	)

	// Fan-out workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				res := c.Run()
				mu.Lock()
				done++
				d := done
				mu.Unlock()
				ch <- Progress{
					Result: checks.CheckResult{Check: c, Result: res},
					Done:   d,
					Total:  total,
				}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, c := range cs {
			jobs <- c
		}
		close(jobs)
		wg.Wait()
		close(ch)
	}()

	return ch
}
