// FROST signing nonces must not be cloneable.
fn assert_clone<T: Clone>() {}

fn main() {
    assert_clone::<libtss::frost::SigningNonces>();
}
