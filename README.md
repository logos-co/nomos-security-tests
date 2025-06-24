# Dispersal Resilience Testbed

A branch to serve as a repository with Nomos node modifications for E2E tests included in [Test/dispersal resilience](https://github.com/logos-co/nomos-e2e-tests/pull/19)

## Covered Modifications

- [DA Message Transformer](https://github.com/logos-co/nomos-security-tests/pull/2/commits/b62dfc02d52b2bf9d50bbb211c6104d1d2b7c7ba)
- [MAX_BLS12_381_ENCODING_CHUNK_SIZE to 30](https://github.com/logos-co/nomos-security-tests/pull/3/commits/7f54114b6c320dc32577b0e8bb85c2d543b4bd56)
- [Modify RS encode function](https://github.com/logos-co/nomos-security-tests/pull/2/commits/0a01ddb323d2b5f9600e26345c14d8fa1d7cbe40) 

## Build Requirements

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


