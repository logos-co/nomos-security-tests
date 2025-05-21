# Nomos Security Tests

A customized fork of the Nomos node with tailored components and tests for security and robustness evaluation.

## Requirements

- **Rust**
    - We aim to maintain compatibility with the latest stable version of Rust.
    - [Installation Guide](https://www.rust-lang.org/tools/install)

- **Risc0**
    - Required for zero-knowledge proof functionality.
    - [Installation Guide](https://dev.risczero.com/api/zkvm/install)


## Running Tests

To run the default test suite, use:

```bash
cargo test
```

To run tests specific to a selected branch, switch to the appropriate branch first. Complex tests which include several nodes could be run from the [nomos-e2e-tests](https://github.com/logos-co/nomos-e2e-tests) repository.


## License

This project is primarily distributed under the terms defined by either the MIT license or the
Apache License (Version 2.0), at your option.

See [LICENSE-APACHE2.0](LICENSE-APACHE2.0) and [LICENSE-MIT](LICENSE-MIT) for details.


