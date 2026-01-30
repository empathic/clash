
## Rust
* All dependencies should be managed in the workspace Cargo.toml file.

## Platforms
* OS: linux + macos
* ARCH: amd64 + arm64

## Testing
* `just check` for unit tests and linting
* `just clester` for end-to-end tests (runs clester against clash binary)
* `just ci` for full CI (check + clester)
* End-to-end test scripts are YAML files in `clester/tests/scripts/`
* The `clester` crate is the end-to-end test harness; see its source for script format

## Development
* Create a new directory within the `plans` and put larger "project" level plans in there and update as you accomplish work.
