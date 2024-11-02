package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func main() {
	// Parse command-line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <pubkey>\n", os.Args[0])
		flag.PrintDefaults()
	}

	var help bool
	var ignoreOnion bool
	var defaultRelaysFile string
	var ignoreRelaysFile string
	var coverTimes int

	flag.BoolVar(&help, "help", false, "Show usage information")
	flag.BoolVar(&ignoreOnion, "ignore-onion", false, "Ignore relays with .onion domains")
	flag.StringVar(&defaultRelaysFile, "default-relays-file", "", "Path to file containing default relays")
	flag.StringVar(&ignoreRelaysFile, "ignore-relays-file", "", "Path to file containing ignored relays")
	flag.IntVar(&coverTimes, "cover-times", 2, "Number of times each pubkey should be covered (must be >= 1)")
	flag.Parse()

	if help || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if coverTimes < 1 {
		log.Fatalf("Invalid value for --cover-times: %d (must be >= 1)", coverTimes)
	}

	// Get the pubkey from the command-line argument
	pubkeyInput := flag.Arg(0)
	pubkeyHex, err := processHexPubkey(pubkeyInput)
	if err != nil {
		log.Fatalf("Invalid pubkey %s: %v", pubkeyInput, err)
	}

	// Initialize default relays
	var initialRelays []string
	if defaultRelaysFile != "" {
		// Read default relays from file
		initialRelays, err = readRelaysFromFile(defaultRelaysFile)
		if err != nil {
			log.Fatalf("Error reading default relays from file: %v", err)
		}
	} else {
		// Default relays to connect to
		initialRelays = []string{
			"wss://relay.damus.io",
			"wss://relay.shitforce.one",
			"wss://eden.nostr.land",
			"wss://relay.primal.net",
			"wss://ditto.pub/relay",
			"wss://nostr.mom",
			"wss://wot.nostr.sats4.life/inbox",
		}
	}

	// Normalize the initial relays to remove trailing slashes
	for i, relayURL := range initialRelays {
		initialRelays[i] = normalizeRelayURL(relayURL)
	}

	// Initialize ignore list of relays
	var ignoreRelays []string
	if ignoreRelaysFile != "" {
		// Read ignored relays from file
		ignoreRelays, err = readRelaysFromFile(ignoreRelaysFile)
		if err != nil {
			log.Fatalf("Error reading ignored relays from file: %v", err)
		}
	} else {
		// No default ignored relays; the list remains empty
		ignoreRelays = []string{}
	}

	// Normalize the ignore relays
	normalizedIgnoreRelays := make(map[string]bool)
	for _, relay := range ignoreRelays {
		normalizedRelay := normalizeRelayURL(relay)
		normalizedIgnoreRelays[normalizedRelay] = true
	}

	// Create a context for the SimplePool
	ctx := context.Background()

	// Create a simple pool of relays
	relayPool := nostr.NewSimplePool(ctx)

	// Add relays to the pool
	for _, url := range initialRelays {
		relayPool.EnsureRelay(url)
	}

	// Fetch the kind 3 event (contact list) for the provided pubkey
	follows, err := getFollowsFromKind3(ctx, relayPool, pubkeyHex, initialRelays)
	if err != nil {
		log.Fatalf("Error fetching follows for pubkey %s: %v", pubkeyInput, err)
	}

	if len(follows) == 0 {
		log.Fatalf("No follows found for pubkey %s", pubkeyInput)
	}

	// Use the extracted pubkeys
	pubkeys := follows

	// Batch the pubkeys into groups of up to 100
	batches := batchPubkeys(pubkeys, 100)

	// Mapping from pubkey to list of relays
	pubkeyRelays := make(map[string][]string)
	var mu sync.Mutex

	// Process each batch
	for _, batch := range batches {
		// Validate and process the hex pubkeys in the batch
		validPubkeys := []string{}
		for _, pk := range batch {
			pubkeyHex, err := processHexPubkey(pk)
			if err != nil {
				log.Printf("Invalid pubkey %s: %v", pk, err)
				continue
			}
			validPubkeys = append(validPubkeys, pubkeyHex)
		}

		if len(validPubkeys) == 0 {
			continue
		}

		// Get relays for the batch of pubkeys
		relaysForBatch, err := getRelaysForPubkeys(ctx, relayPool, validPubkeys, initialRelays)
		if err != nil {
			log.Printf("Error getting relays for batch: %v", err)
			continue
		}

		// Merge the results into pubkeyRelays
		mu.Lock()
		for pk, relays := range relaysForBatch {
			pubkeyRelays[pk] = relays
		}
		mu.Unlock()
	}

	// Build mapping from relay to set of pubkeys, excluding ignored relays and optionally .onion domains
	relayPubkeys := make(map[string]map[string]bool)
	for pk, relays := range pubkeyRelays {
		for _, relay := range relays {
			normalizedRelay := normalizeRelayURL(relay)
			if normalizedIgnoreRelays[normalizedRelay] {
				// Skip relays in the ignore list
				continue
			}
			if ignoreOnion {
				// Parse the relay URL to check for .onion domains
				parsedURL, err := url.Parse(normalizedRelay)
				if err == nil && strings.HasSuffix(parsedURL.Hostname(), ".onion") {
					// Skip .onion domains if ignoreOnion is true
					continue
				}
			}
			if _, ok := relayPubkeys[normalizedRelay]; !ok {
				relayPubkeys[normalizedRelay] = make(map[string]bool)
			}
			relayPubkeys[normalizedRelay][pk] = true
		}
	}

	// Compute relay popularity (number of pubkeys that include the relay)
	relayPopularity := make(map[string]int)
	for relay, pks := range relayPubkeys {
		relayPopularity[relay] = len(pks)
	}

	// Apply greedy multi-cover set cover algorithm with relay popularity
	minRelays := greedySetMultiCover(pubkeys, relayPubkeys, coverTimes, relayPopularity) // Pass relayPopularity

	fmt.Printf("Minimum set of public relays to subscribe to (each pubkey covered at least %d times):\n", coverTimes)
	for _, relay := range minRelays {
		fmt.Println(relay)
	}
}

func readRelaysFromFile(filename string) ([]string, error) {
	var relays []string

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open relays file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			// Skip empty lines and comments
			continue
		}
		relays = append(relays, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading relays file: %w", err)
	}

	return relays, nil
}

func batchPubkeys(pubkeys []string, batchSize int) [][]string {
	var batches [][]string
	for batchSize < len(pubkeys) {
		pubkeys, batches = pubkeys[batchSize:], append(batches, pubkeys[0:batchSize:batchSize])
	}
	batches = append(batches, pubkeys)
	return batches
}

func processHexPubkey(pk string) (string, error) {
	// Remove any leading '0x' or other prefixes
	pk = strings.TrimPrefix(pk, "0x")
	pk = strings.TrimSpace(pk)

	// Validate the length of the hex string (should be 64 characters for 32 bytes)
	if len(pk) != 64 {
		return "", fmt.Errorf("invalid length: expected 64 hex characters")
	}

	// Decode the hex string to ensure it's valid hex
	_, err := hex.DecodeString(pk)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %v", err)
	}

	return pk, nil
}

func normalizeRelayURL(relay string) string {
	// Parse the URL
	parsedURL, err := url.Parse(relay)
	if err != nil {
		// If parsing fails, return the original relay URL
		return relay
	}

	// Remove trailing slashes from the path
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")

	// Reconstruct the URL without the trailing slash
	return parsedURL.String()
}

func getFollowsFromKind3(ctx context.Context, relayPool *nostr.SimplePool, pubkey string, initialRelays []string) ([]string, error) {
	// Prepare the filter to get kind 3 events for the pubkey
	filter := nostr.Filter{
		Authors: []string{pubkey},
		Kinds:   []int{3},
		Limit:   1,
	}

	// Create a context with timeout for this subscription
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use SubManyEose to subscribe to multiple relays
	events := relayPool.SubManyEose(timeoutCtx, initialRelays, []nostr.Filter{filter})

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				// Channel closed
				return nil, fmt.Errorf("No kind 3 event found for pubkey %s", pubkey)
			}
			if ev.Event == nil {
				continue
			}
			// Extract pubkeys from 'p' tags
			var follows []string
			for _, tag := range ev.Event.Tags {
				if tag[0] == "p" && len(tag) > 1 {
					pk := tag[1]
					follows = append(follows, pk)
				}
			}
			return follows, nil
		case <-timeoutCtx.Done():
			// Timeout reached
			return nil, fmt.Errorf("Timeout fetching kind 3 event for pubkey %s", pubkey)
		}
	}
}

func getRelaysForPubkeys(ctx context.Context, relayPool *nostr.SimplePool, pubkeys []string, initialRelays []string) (map[string][]string, error) {
	// Prepare the filter
	filter := nostr.Filter{
		Authors: pubkeys,
		Kinds:   []int{10002},
	}

	// Create a context with timeout for this subscription
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use SubManyEose to subscribe to multiple relays
	events := relayPool.SubManyEose(timeoutCtx, initialRelays, []nostr.Filter{filter})

	// Map to collect relay URLs for each pubkey
	pubkeyToRelays := make(map[string][]string)

	// Set to keep track of pubkeys we are waiting for
	pendingPubkeys := make(map[string]struct{})
	for _, pk := range pubkeys {
		pendingPubkeys[pk] = struct{}{}
	}

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				// Channel closed
				return pubkeyToRelays, nil
			}
			if ev.Event == nil {
				continue
			}

			pk := ev.Event.PubKey

			if _, ok := pendingPubkeys[pk]; !ok {
				// Either we already received an event for this pubkey, or it's not in our list
				continue
			}

			// Extract relay URLs from 'r' tags
			var relayURLs []string
			for _, tag := range ev.Event.Tags {
				if tag[0] == "r" && len(tag) > 1 {
					normalizedRelay := normalizeRelayURL(tag[1])
					// Avoid duplicates
					if !contains(relayURLs, normalizedRelay) {
						relayURLs = append(relayURLs, normalizedRelay)
					}
				}
			}

			pubkeyToRelays[pk] = relayURLs
			delete(pendingPubkeys, pk)

			// If we have received events for all pubkeys, we can return
			if len(pendingPubkeys) == 0 {
				return pubkeyToRelays, nil
			}

		case <-timeoutCtx.Done():
			// Timeout reached
			return pubkeyToRelays, nil
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Function to ensure each pubkey is covered at least k times, preferring more popular relays
func greedySetMultiCover(pubkeys []string, relayPubkeys map[string]map[string]bool, k int, relayPopularity map[string]int) []string {
	// Initialize the count of covers needed for each pubkey
	coversNeeded := make(map[string]int)
	for _, pk := range pubkeys {
		coversNeeded[pk] = k
	}

	var result []string

	for {
		var bestRelay string
		maxCovered := 0
		maxPopularity := -1

		// Find the relay that covers the most needed covers, prefer more popular relays
		for relay, pks := range relayPubkeys {
			covered := 0
			for pk := range pks {
				if coversNeeded[pk] > 0 {
					covered++
				}
			}
			if covered > maxCovered {
				maxCovered = covered
				bestRelay = relay
				maxPopularity = relayPopularity[relay]
			} else if covered == maxCovered {
				// Break ties by choosing the relay with higher popularity
				popularity := relayPopularity[relay]
				if popularity > maxPopularity {
					bestRelay = relay
					maxPopularity = popularity
				}
			}
		}

		if maxCovered == 0 {
			// No relay covers any more needed covers
			break
		}

		// Add the best relay to the result
		result = append(result, bestRelay)

		// Decrease the covers needed for pubkeys covered by this relay
		for pk := range relayPubkeys[bestRelay] {
			if coversNeeded[pk] > 0 {
				coversNeeded[pk]--
			}
		}

		// Remove the selected relay from consideration
		delete(relayPubkeys, bestRelay)

		// Check if all pubkeys have been covered at least k times
		allCovered := true
		for _, needed := range coversNeeded {
			if needed > 0 {
				allCovered = false
				break
			}
		}
		if allCovered {
			break
		}
	}

	return result
}
