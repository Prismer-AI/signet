use crate::error::SignetError;
use crate::receipt::{Action, Receipt};
use ed25519_dalek::SigningKey;

pub fn sign(
    _key: &SigningKey,
    _action: &Action,
    _signer_name: &str,
    _signer_owner: &str,
) -> Result<Receipt, SignetError> {
    todo!()
}
