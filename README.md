# Relay Finder
Relay Finder is a tool designed to help you find the minimum set of public relays to subscribe to, ensuring that you share at least specified number of relays with the pubkeys you follow.

## Introduction

Relay Finder connects to a set of relays and fetches the contact list for a given pubkey. It then determines the minimum set of relays needed to cover all the pubkeys in the contact list at least a specified number of times.

## Usage

To use Relay Finder, run the following command:

```sh
relay-finder [options] <pubkey>
```

### Options

- `--help`: Show usage information.
- `--ignore-onion`: Ignore relays with `.onion` domains.
- `--default-relays-file <path>`: Path to file containing the relays to query for follower and relays list events (optional, will default to a pre-defined list).
- `--ignore-relays-file <path>`: Path to file containing ignored relays (so you can avoid paid or private relays).
- `--cover-times <number>`: Number of times each pubkey should be covered (must be >= 1).

### Example

```sh
relay-finder --default-relays-file relays.txt --ignore-relays-file ignore.txt --cover-times 3 <pubkey>
```

## Building

To build the program, follow these steps:

1. Ensure you have [Go](https://golang.org/) installed.
2. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/relay-finder.git
    ```
3. Navigate to the project directory:
    ```sh
    cd relay-finder
    ```
4. Build the program:
    ```sh
    go build -o relay-finder
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.