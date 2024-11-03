# Relay Finder

Relay Finder is a tool designed to help you find the minimum set of public relays to subscribe to, ensuring that you share at least a specified number of relays with the pubkeys you follow.

## Introduction

Relay Finder connects to a set of relays and fetches the contact lists (kind 3 events) for the provided pubkeys. It then determines the minimum set of relays needed to cover all the pubkeys in the contact lists at least a specified number of times.

## Features

- **Optimized Relay Selection:** Uses a greedy algorithm to find the minimum set of relays covering your follows.
- **Flexible Filtering Options:** Allows you to ignore onion addresses, non-TLS relays, local addresses, and relays using non-standard ports.
- **Detailed Output:** Optionally displays detailed relay coverage information, including the number of pubkeys each relay covers.
- **Supports Multiple Pubkeys:** You can provide multiple pubkeys directly or via a file.

## Usage

To use Relay Finder, run the following command:

```sh
relay-finder [options] [<pubkey>...]
```

### Options

- `--help`: Show usage information.
- `--pubkeys-file <path>`: Path to a file containing pubkeys (one per line).
- `--default-relays-file <path>`: Path to a file containing the initial relays to query for follower and relay list events (optional; will default to a pre-defined list if not provided).
- `--ignore-relays-file <path>`: Path to a file containing ignored relays (so you can avoid paid or private relays).
- `--cover-times <number>`: Number of times each pubkey should be covered (must be >= 1).
- `--verbose`: Print detailed relay coverage information.
- `--ignore-onion`: Ignore relays with `.onion` domains.
- `--ignore-non-tls`: Ignore non-TLS relays (`ws://`).
- `--ignore-local`: Ignore local addresses (`.local`, `.lan`, private IP ranges).
- `--ignore-non-standard-ports`: Ignore relay URLs with non-standard ports.

### Examples

#### Basic Usage with a Single Pubkey

```sh
relay-finder --cover-times 2 <pubkey>
```

#### Using a Pubkeys File and Verbose Output

```sh
relay-finder --pubkeys-file pubkeys.txt --cover-times 2 --verbose
```

#### Ignoring Onion Addresses and Non-TLS Relays

```sh
relay-finder --pubkeys-file pubkeys.txt --ignore-onion --ignore-non-tls
```

#### Ignoring Local Addresses and Non-Standard Ports

```sh
relay-finder --pubkeys-file pubkeys.txt --ignore-local --ignore-non-standard-ports
```

#### Using Default and Ignore Relays Files

```sh
relay-finder --default-relays-file relays.txt --ignore-relays-file ignore.txt --cover-times 3 <pubkey>
```

## Input Options

You can provide pubkeys in two ways:

1. **Directly as Command-Line Arguments:**

   ```sh
   relay-finder <pubkey1> <pubkey2> ...
   ```

2. **Via a Pubkeys File:**

   Create a file (e.g., `pubkeys.txt`) with one pubkey per line, then use:

   ```sh
   relay-finder --pubkeys-file pubkeys.txt
   ```

## Output

The program outputs the minimum set of public relays to subscribe to, ensuring that each pubkey is covered at least the specified number of times.

- **Without `--verbose`:** Only the relay URLs are listed.

  ```
  wss://relay.damus.io
  wss://eden.nostr.land
  wss://relay.snort.social
  ```

- **With `--verbose`:** Detailed information is provided, including the number of pubkeys each relay covers.

  ```
  wss://relay.damus.io (covers 45 pubkeys)
  wss://eden.nostr.land (covers 30 pubkeys)
  wss://relay.singleuser.com (covers pubkey: npub1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)
  ```

## Building

To build the program, follow these steps:

1. **Install Go:**

   Ensure you have [Go](https://golang.org/dl/) installed (version 1.16 or later).

2. **Clone the Repository:**

   ```sh
   git clone https://github.com/yourusername/relay-finder.git
   ```

3. **Navigate to the Project Directory:**

   ```sh
   cd relay-finder
   ```

4. **Install Dependencies:**

   ```sh
   go get -u ./...
   go mod tidy
   ```

5. **Build the Program:**

   ```sh
   go build -o relay-finder
   ```

## Dependencies

Relay Finder depends on the following Go packages:

- [github.com/nbd-wtf/go-nostr](https://github.com/nbd-wtf/go-nostr): Nostr protocol implementation.
- [github.com/schollz/progressbar](https://github.com/schollz/progressbar): For displaying progress bars during data fetching.

## Additional Notes

- **Relay Selection Algorithm:** The program uses a greedy set cover algorithm to select relays, prioritizing relays that cover the most pubkeys.
- **Error Handling:** The program gracefully handles invalid pubkeys and relay URLs, skipping over them and continuing execution.
- **Customization:** You can customize the list of initial relays and ignored relays by providing files via `--default-relays-file` and `--ignore-relays-file`.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.