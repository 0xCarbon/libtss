// DKLs23 Party<secp256r1> must NOT implement Copy (secrets should not be trivially copyable).
fn assert_copy<T: Copy>() {}

fn main() {
    assert_copy::<dkls23_secp256r1::Party>();
}
