build:
    cargo build
    
fmt:
    cargo fmt
    
lint:
    cargo fmt -- --check
    cargo clippy -- -D warnings

test:
    cargo test --all-features

ready: fmt lint test
    @echo "Ready!"

doc:
    cargo doc --no-deps --all-features
    
opendoc:
    cargo doc --no-deps --all-features --open
