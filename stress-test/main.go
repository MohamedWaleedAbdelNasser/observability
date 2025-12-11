package main

import (
	"fmt"
	"os"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

const (
	authServerURL = "http://localhost:8081"
)

func main() {
	fmt.Println("")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("  VEGETA STRESS TEST - AuthServer")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("")

	tests := []struct {
		name     string
		rate     int
		duration time.Duration
	}{
		{"Light Load", 10, 5 * time.Second},
		{"Medium Load", 50, 10 * time.Second},
		{"Heavy Load", 100, 10 * time.Second},
		{"Very Heavy Load", 200, 10 * time.Second},
	}

	target := vegeta.Target{
		Method: "GET",
		URL:    authServerURL + "/authorize?response_type=code&client_id=stress-test-client&redirect_uri=http://localhost:8080/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=vegeta-test",
	}

	targeter := vegeta.NewStaticTargeter(target)

	for i, test := range tests {
		fmt.Printf("[Test %d] %s: %d req/sec for %v\n", i+1, test.name, test.rate, test.duration)
		fmt.Println("─────────────────────────────────────────────────────────────────")

		metrics := runLoadTest(targeter, test.rate, test.duration, test.name)
		printMetrics(metrics)
		fmt.Println("")

		if i < len(tests)-1 {
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("  STRESS TEST COMPLETE!")
	fmt.Println("════════════════════════════════════════════════════════════════")
	fmt.Println("")

}

func runLoadTest(targeter vegeta.Targeter, ratePerSec int, duration time.Duration, name string) *vegeta.Metrics {
	rate := vegeta.Rate{Freq: ratePerSec, Per: time.Second}
	attacker := vegeta.NewAttacker()

	var metrics vegeta.Metrics

	for res := range attacker.Attack(targeter, rate, duration, name) {
		metrics.Add(res)
	}
	metrics.Close()

	return &metrics
}

func printMetrics(m *vegeta.Metrics) {
	fmt.Printf("  Requests:      %d\n", m.Requests)
	fmt.Printf("  Rate:          %.2f req/sec\n", m.Rate)
	fmt.Printf("  Throughput:    %.2f req/sec\n", m.Throughput)
	fmt.Printf("  Success:       %.2f%%\n", m.Success*100)
	fmt.Printf("  Duration:      %v\n", m.Duration.Round(time.Millisecond))
	fmt.Println("")
	fmt.Println("  Latencies:")
	fmt.Printf("    Min:         %v\n", m.Latencies.Min.Round(time.Microsecond))
	fmt.Printf("    Mean:        %v\n", m.Latencies.Mean.Round(time.Microsecond))
	fmt.Printf("    P50:         %v\n", m.Latencies.P50.Round(time.Microsecond))
	fmt.Printf("    P90:         %v\n", m.Latencies.P90.Round(time.Microsecond))
	fmt.Printf("    P95:         %v\n", m.Latencies.P95.Round(time.Microsecond))
	fmt.Printf("    P99:         %v\n", m.Latencies.P99.Round(time.Microsecond))
	fmt.Printf("    Max:         %v\n", m.Latencies.Max.Round(time.Microsecond))
	fmt.Println("")

	fmt.Println("  Status Codes:")
	for code, count := range m.StatusCodes {
		fmt.Printf("    %s: %d\n", code, count)
	}

	if len(m.Errors) > 0 {
		fmt.Println("")
		fmt.Println("  Errors:")
		for _, err := range m.Errors {
			fmt.Printf("    - %s\n", err)
		}
	}

	fmt.Println("")
	if m.Success == 1.0 {
		fmt.Println("  ✓ All requests successful!")
	} else if m.Success >= 0.99 {
		fmt.Println("  ⚠ Some requests failed")
	} else {
		fmt.Println("  ✗ Significant failures detected")
		os.Exit(1)
	}
}
