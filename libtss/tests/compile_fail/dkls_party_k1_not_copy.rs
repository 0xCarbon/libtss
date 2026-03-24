// DKLs23 Party<secp256k1> must NOT implement Copy (secrets should not be trivially copyable).
fn assert_copy<T: Copy>() {}

fn main() {
    assert_copy::<dkls23_secp256k1::Party>();
}
