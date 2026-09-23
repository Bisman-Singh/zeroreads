// Command loggen writes deterministic ground-truth logs for one service to stdout.
//
// The same --seed, --service and --count always produce the same lines, so a test harness can
// recompute the exact ground truth in-process instead of shipping it out of the cluster.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Bisman-Singh/sievelog/internal/gen"
)

func main() {
	service := flag.String("service", "", "service from the corpus to emit")
	seed := flag.Uint64("seed", 1, "PRNG seed")
	count := flag.Int("count", 1000, "number of lines to emit")
	rate := flag.Int("rate", 0, "lines per second (0 = as fast as possible)")
	hold := flag.Bool("hold", false, "keep running after the last line so the container is not restarted")
	flag.Parse()

	g, err := gen.New(*service, *seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	w := bufio.NewWriter(os.Stdout)
	var tick *time.Ticker
	if *rate > 0 {
		tick = time.NewTicker(time.Second / time.Duration(*rate))
		defer tick.Stop()
	}
	for i := 0; i < *count; i++ {
		if tick != nil {
			<-tick.C
		}
		fmt.Fprintln(w, g.Next().Line)
		if tick != nil {
			w.Flush()
		}
	}
	w.Flush()
	// Nothing else is written to stdout or stderr: the container's log stream is the ground truth.
	if *hold {
		select {}
	}
}
