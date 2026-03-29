use crate::error::SignetError;
use crate::receipt::Receipt;
use ed25519_dalek::VerifyingKey;

pub fn verify(_receipt: &Receipt, _pubkey: &VerifyingKey) -> Result<(), SignetError> {
    todo!()
}
