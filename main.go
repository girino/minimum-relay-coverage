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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/schollz/progressbar/v3"
)

type RelayInfo struct {
	Relay      string
	NumPubkeys int
	Pubkeys    []string
}

func main() {
	// Parse command-line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [<pubkey>]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var help bool
	var ignoreOnion bool
	var ignoreNonTLS bool
	var defaultRelaysFile string
	var ignoreRelaysFile string
	var coverTimes int
	var pubkeysFile string
	var verbose bool

	flag.BoolVar(&help, "help", false, "Show usage information")
	flag.BoolVar(&ignoreOnion, "ignore-onion", false, "Ignore relays with .onion domains")
	flag.BoolVar(&ignoreNonTLS, "ignore-non-tls", false, "Ignore non-TLS relays (ws://)")
	flag.StringVar(&defaultRelaysFile, "default-relays-file", "", "Path to file containing default relays")
	flag.StringVar(&ignoreRelaysFile, "ignore-relays-file", "", "Path to file containing ignored relays")
	flag.IntVar(&coverTimes, "cover-times", 2, "Number of times each pubkey should be covered (must be >= 1)")
	flag.StringVar(&pubkeysFile, "pubkeys-file", "", "Path to file containing pubkeys")
	flag.BoolVar(&verbose, "verbose", false, "Print detailed relay coverage information")
	flag.Parse()

	if help || (flag.NArg() == 0 && pubkeysFile == "") {
		flag.Usage()
		os.Exit(1)
	}

	if coverTimes < 1 {
		log.Fatalf("Invalid value for --cover-times: %d (must be >= 1)", coverTimes)
	}

	var err error // Declare err once to avoid redeclaration

	// Initialize list of pubkeys
	var pubkeys []string

	if pubkeysFile != "" {
		// Read pubkeys from file
		var filePubkeys []string
		filePubkeys, err = readPubkeysFromFile(pubkeysFile)
		if err != nil {
			log.Fatalf("Error reading pubkeys from file: %v", err)
		}
		pubkeys = filePubkeys
	} else if flag.NArg() >= 1 {
		// Use pubkey(s) from command-line arguments
		pubkeys = flag.Args()
	} else {
		log.Fatalf("No pubkeys provided. Use --pubkeys-file or provide a pubkey as an argument.")
	}

	// Validate and process the hex pubkeys
	var validPubkeys []string
	for _, pk := range pubkeys {
		pubkeyHex, err := processHexPubkey(pk)
		if err != nil {
			log.Printf("Invalid pubkey %s: %v", pk, err)
			continue
		}
		validPubkeys = append(validPubkeys, pubkeyHex)
	}

	if len(validPubkeys) == 0 {
		log.Fatalf("No valid pubkeys provided.")
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

	// Normalize and validate the initial relays
	initialRelays = filterRelays(initialRelays, ignoreNonTLS)
	var validInitialRelays []string
	for _, relayURL := range initialRelays {
		normalizedRelay := normalizeRelayURL(relayURL)
		if isValidRelayURL(normalizedRelay) {
			validInitialRelays = append(validInitialRelays, normalizedRelay)
		}
	}
	initialRelays = validInitialRelays

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

	// Normalize and validate the ignore relays
	normalizedIgnoreRelays := make(map[string]bool)
	ignoreRelays = filterRelays(ignoreRelays, ignoreNonTLS)
	for _, relay := range ignoreRelays {
		normalizedRelay := normalizeRelayURL(relay)
		if isValidRelayURL(normalizedRelay) {
			normalizedIgnoreRelays[normalizedRelay] = true
		}
	}

	// Create a context for the SimplePool
	ctx := context.Background()

	// Create a simple pool of relays
	relayPool := nostr.NewSimplePool(ctx)

	// Add relays to the pool
	for _, url := range initialRelays {
		relayPool.EnsureRelay(url)
	}

	// Fetch the kind 3 events (contact lists) for the provided pubkeys
	fmt.Println("Fetching kind 3 events (contact lists) for the provided pubkeys...")
	follows, err := getFollowsFromKind3Batch(ctx, relayPool, validPubkeys, initialRelays)
	if err != nil {
		log.Fatalf("Error fetching follows: %v", err)
	}

	if len(follows) == 0 {
		log.Fatalf("No follows found for the provided pubkeys.")
	}

	// Use the collected follows as the pubkeys to process
	followsPubkeys := follows

	// Batch the follows pubkeys into groups of up to 100
	batches := batchPubkeys(followsPubkeys, 100)

	// Mapping from pubkey to list of relays
	pubkeyRelays := make(map[string][]string)
	var mu sync.Mutex

	// Fetch relays for the collected follows
	fmt.Println("Fetching relays for the collected follows...")
	totalBatches := len(batches)
	bar := progressbar.Default(int64(totalBatches), "Fetching relays")
	for _, batch := range batches {
		// Validate and process the hex pubkeys in the batch
		validBatchPubkeys := []string{}
		for _, pk := range batch {
			pubkeyHex, err := processHexPubkey(pk)
			if err != nil {
				log.Printf("Invalid pubkey %s: %v", pk, err)
				continue
			}
			validBatchPubkeys = append(validBatchPubkeys, pubkeyHex)
		}

		if len(validBatchPubkeys) == 0 {
			bar.Add(1)
			continue
		}

		// Get relays for the batch of pubkeys
		relaysForBatch, err := getRelaysForPubkeys(ctx, relayPool, validBatchPubkeys, initialRelays, ignoreNonTLS)
		if err != nil {
			log.Printf("Error getting relays for batch: %v", err)
			bar.Add(1)
			continue
		}

		// Merge the results into pubkeyRelays
		mu.Lock()
		for pk, relays := range relaysForBatch {
			validRelays := []string{}
			for _, relay := range relays {
				if isValidRelayURL(relay) {
					validRelays = append(validRelays, relay)
				}
			}
			pubkeyRelays[pk] = validRelays
		}
		mu.Unlock()

		bar.Add(1)
	}

	// Build mapping from relay to set of pubkeys, excluding ignored relays and optionally .onion domains
	fmt.Println("Processing relay and pubkey mappings...")
	relayPubkeys := make(map[string]map[string]bool)
	for pk, relays := range pubkeyRelays {
		for _, relay := range relays {
			normalizedRelay := normalizeRelayURL(relay)
			if !isValidRelayURL(normalizedRelay) {
				continue // Skip invalid relay URLs
			}
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
			if ignoreNonTLS {
				// Skip non-TLS relays if ignoreNonTLS is true
				parsedURL, err := url.Parse(normalizedRelay)
				if err == nil && parsedURL.Scheme != "wss" {
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

	// Make a copy of relayPubkeys before passing to greedySetMultiCover
	relayPubkeysCopy := copyRelayPubkeys(relayPubkeys)

	// Apply greedy multi-cover set cover algorithm with relay popularity
	fmt.Println("Computing minimum set of relays using greedy algorithm...")
	minRelays := greedySetMultiCover(followsPubkeys, relayPubkeys, coverTimes, relayPopularity) // Pass relayPopularity

	// Prepare the relay information for sorting
	relayInfos := []RelayInfo{}
	for _, relay := range minRelays {
		pubkeysCovered := relayPubkeysCopy[relay]
		numPubkeys := len(pubkeysCovered)
		pubkeyList := []string{}
		for pk := range pubkeysCovered {
			pubkeyList = append(pubkeyList, pk)
		}
		relayInfos = append(relayInfos, RelayInfo{
			Relay:      relay,
			NumPubkeys: numPubkeys,
			Pubkeys:    pubkeyList,
		})
	}

	// Sort the relayInfos slice by NumPubkeys in descending order
	sort.Slice(relayInfos, func(i, j int) bool {
		return relayInfos[i].NumPubkeys > relayInfos[j].NumPubkeys
	})

	fmt.Printf("\nMinimum set of public relays to subscribe to (each pubkey covered at least %d times):\n", coverTimes)
	for _, relayInfo := range relayInfos {
		relay := relayInfo.Relay
		numPubkeys := relayInfo.NumPubkeys
		pubkeysCovered := relayInfo.Pubkeys

		if verbose {
			if numPubkeys == 1 {
				npub, err := nip19.EncodePublicKey(pubkeysCovered[0])
				if err != nil {
					npub = pubkeysCovered[0]
				}
				fmt.Printf("%s (covers pubkey: %s)\n", relay, npub)
			} else {
				fmt.Printf("%s (covers %d pubkeys)\n", relay, numPubkeys)
			}
		} else {
			fmt.Println(relay)
		}
	}
}

func copyRelayPubkeys(original map[string]map[string]bool) map[string]map[string]bool {
	copy := make(map[string]map[string]bool)
	for relay, pubkeys := range original {
		pubkeysCopy := make(map[string]bool)
		for pk := range pubkeys {
			pubkeysCopy[pk] = true
		}
		copy[relay] = pubkeysCopy
	}
	return copy
}

func readPubkeysFromFile(filename string) ([]string, error) {
	var pubkeys []string

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pubkeys file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			// Skip empty lines and comments
			continue
		}
		pubkeys = append(pubkeys, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading pubkeys file: %w", err)
	}

	return pubkeys, nil
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

func filterRelays(relays []string, ignoreNonTLS bool) []string {
	var filtered []string
	for _, relay := range relays {
		if ignoreNonTLS {
			parsedURL, err := url.Parse(relay)
			if err != nil {
				continue // Skip invalid URLs
			}
			if parsedURL.Scheme != "wss" {
				continue // Skip non-TLS relays
			}
		}
		filtered = append(filtered, relay)
	}
	return filtered
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

func isValidRelayURL(relay string) bool {
	parsedURL, err := url.Parse(relay)
	if err != nil {
		return false
	}
	if parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss" {
		return false
	}
	if parsedURL.Host == "" {
		return false
	}
	return true
}

func getFollowsFromKind3Batch(ctx context.Context, relayPool *nostr.SimplePool, pubkeys []string, initialRelays []string) ([]string, error) {
	// Map to store the latest event per pubkey
	latestEvents := make(map[string]*nostr.Event)
	var mu sync.Mutex

	// Batch the pubkeys into groups of up to 20
	batches := batchPubkeys(pubkeys, 20)

	totalBatches := len(batches)
	bar := progressbar.Default(int64(totalBatches), "Fetching kind 3 events")

	for _, batch := range batches {
		// Prepare the filter to get kind 3 events for the pubkeys
		filter := nostr.Filter{
			Authors: batch,
			Kinds:   []int{3},
		}

		// Create a context with timeout for this subscription
		timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		// Use SubManyEose to subscribe to multiple relays
		events := relayPool.SubManyEose(timeoutCtx, initialRelays, []nostr.Filter{filter})

	OuterLoop:
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					// Channel closed
					break OuterLoop
				}
				if ev.Event == nil {
					continue
				}
				pubkey := ev.Event.PubKey

				mu.Lock()
				existingEvent, exists := latestEvents[pubkey]
				if !exists || ev.Event.CreatedAt > existingEvent.CreatedAt {
					// Update the latest event for this pubkey
					latestEvents[pubkey] = ev.Event
				}
				mu.Unlock()
			case <-timeoutCtx.Done():
				// Timeout reached
				break OuterLoop
			}
		}

		bar.Add(1)
	}

	// Now extract follows from the latest events
	followsSet := make(map[string]struct{})
	for _, event := range latestEvents {
		for _, tag := range event.Tags {
			if tag[0] == "p" && len(tag) > 1 {
				pk := tag[1]
				followsSet[pk] = struct{}{}
			}
		}
	}

	// Convert set to slice
	var follows []string
	for pk := range followsSet {
		follows = append(follows, pk)
	}

	return follows, nil
}

func getRelaysForPubkeys(ctx context.Context, relayPool *nostr.SimplePool, pubkeys []string, initialRelays []string, ignoreNonTLS bool) (map[string][]string, error) {
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
	latestEventTime := make(map[string]nostr.Timestamp)

	// Set to keep track of pubkeys we are waiting for
	pendingPubkeys := make(map[string]struct{})
	for _, pk := range pubkeys {
		pendingPubkeys[pk] = struct{}{}
	}

OuterLoop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				// Channel closed
				break OuterLoop
			}
			if ev.Event == nil {
				continue
			}

			pk := ev.Event.PubKey

			// Since we might receive multiple events per pubkey, keep the latest one
			mu := sync.Mutex{}
			mu.Lock()
			existingTime, exists := latestEventTime[pk]
			if !exists || ev.Event.CreatedAt > existingTime {
				// Extract relay URLs from 'r' tags
				var relayURLs []string
				for _, tag := range ev.Event.Tags {
					if tag[0] == "r" && len(tag) > 1 {
						normalizedRelay := normalizeRelayURL(tag[1])
						if ignoreNonTLS {
							parsedURL, err := url.Parse(normalizedRelay)
							if err != nil {
								continue // Skip invalid URLs
							}
							if parsedURL.Scheme != "wss" {
								continue // Skip non-TLS relays
							}
						}
						if !isValidRelayURL(normalizedRelay) {
							continue // Skip invalid relay URLs
						}
						// Avoid duplicates
						if !contains(relayURLs, normalizedRelay) {
							relayURLs = append(relayURLs, normalizedRelay)
						}
					}
				}
				pubkeyToRelays[pk] = relayURLs
				latestEventTime[pk] = ev.Event.CreatedAt
			}
			mu.Unlock()

			delete(pendingPubkeys, pk)

			// If we have received events for all pubkeys, we can return
			if len(pendingPubkeys) == 0 {
				break OuterLoop
			}

		case <-timeoutCtx.Done():
			// Timeout reached
			break OuterLoop
		}
	}

	return pubkeyToRelays, nil
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
