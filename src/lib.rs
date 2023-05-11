use lazy_static::lazy_static;
use openssl::{pkey::Private, rsa::Rsa};

pub mod connection;
pub mod player;
pub mod protocol;

lazy_static! {
    pub static ref RSA_KEY_PAIR: Rsa<Private> = Rsa::generate(1024).unwrap();
}
