#![cfg(feature = "enclave-se")]

#[test]
fn enclave_se_stub_builds() {
    // This test only ensures the feature-gated module compiles on non-macOS
    // platforms where the real Secure Enclave isn't available. Actual testing
    // requires macOS runners and is out-of-scope for local CI.
    assert!(true);
}
