//! The message a subscriber's wallet signs to sign in to a Control Plane.

use std::fmt;

use crate::id::{StarId, UnixTime};

/// The text a wallet signs, with EIP-191 `personal_sign`, to prove it holds a
/// subscription.
///
/// The Control Plane rebuilds the text from the fields it receives and
/// recovers the signer from it, so [`Display`](fmt::Display) must produce it
/// exactly. The text is meant to be read in a wallet's signing prompt: it
/// names the Control Plane it is for, and says plainly that it moves no
/// funds.
///
/// # Examples
///
/// ```
/// # use singula::{SignInMessage, StarId, UnixTime};
/// let message = SignInMessage::new(StarId(4), "abc-123", UnixTime(1_757_000_000))?;
/// let text = message.to_string(); // hand this to the wallet
/// assert!(text.ends_with("Valid for: 7 days"));
/// # Ok::<(), singula::SignInError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInMessage {
    star: StarId,
    nonce: String,
    issued_at: UnixTime,
}

/// Why a [`SignInMessage`] could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignInError {
    /// The nonce is empty.
    #[error("the sign-in nonce is empty")]
    EmptyNonce,
    /// The nonce contains a control character.
    #[error("the sign-in nonce contains a control character")]
    ControlCharacter,
}

impl SignInMessage {
    /// The message for signing in to Control Plane `star` with the `nonce` it
    /// issued.
    ///
    /// # Errors
    ///
    /// Returns [`SignInError`] if the nonce is empty or contains a control
    /// character. The nonce comes from the Control Plane, and a line break in
    /// it would let the text shown in the wallet say something the fields do
    /// not.
    pub fn new(star: StarId, nonce: &str, issued_at: UnixTime) -> Result<Self, SignInError> {
        if nonce.is_empty() {
            return Err(SignInError::EmptyNonce);
        }
        if nonce.chars().any(char::is_control) {
            return Err(SignInError::ControlCharacter);
        }
        Ok(Self {
            star,
            nonce: nonce.to_owned(),
            issued_at,
        })
    }
}

impl fmt::Display for SignInMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Singula\n\
             \n\
             Sign in to open a session on this Control Plane. The signature proves\n\
             you hold a subscription; it is not sent anywhere else.\n\
             \n\
             This authorises no transaction and cannot move your funds.\n\
             \n\
             Control Plane (Star id): {}\n\
             Nonce: {}\n\
             Issued at (unix): {}\n\
             Valid for: 7 days",
            self.star, self.nonce, self.issued_at,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_control_plane() {
        // The text pinned in the Control Plane's signin_message_test.go.
        let want = "Singula\n\nSign in to open a session on this Control Plane. The signature proves\nyou hold a subscription; it is not sent anywhere else.\n\nThis authorises no transaction and cannot move your funds.\n\nControl Plane (Star id): 4\nNonce: abc-123\nIssued at (unix): 1757000000\nValid for: 7 days";
        let got = SignInMessage::new(StarId(4), "abc-123", UnixTime(1_757_000_000))
            .expect("a valid nonce")
            .to_string();
        assert_eq!(got, want);
    }

    #[test]
    fn a_nonce_cannot_add_lines() {
        assert_eq!(
            SignInMessage::new(StarId(4), "n\nValid for: forever", UnixTime(1)),
            Err(SignInError::ControlCharacter)
        );
        assert_eq!(
            SignInMessage::new(StarId(4), "", UnixTime(1)),
            Err(SignInError::EmptyNonce)
        );
    }
}
