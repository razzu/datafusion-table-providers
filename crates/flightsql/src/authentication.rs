// SPDX-License-Identifier: Apache-2.0

use datafusion::common::{DataFusionError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use tonic::metadata::{Ascii, MetadataValue};

/// Authentication mode with runtime-only credentials.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightAuthentication {
    BearerToken {
        /// Complete authorization header, including its scheme.
        #[serde(skip)]
        token: Option<String>,
    },
    UsernamePassword {
        #[serde(skip)]
        username: Option<String>,
        #[serde(skip)]
        password: Option<String>,
        /// Authorization returned by the handshake, not the login credentials.
        #[serde(skip)]
        authorization: Option<String>,
    },
}

impl fmt::Debug for FlightAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken { .. } => f.debug_struct("BearerToken").finish_non_exhaustive(),
            Self::UsernamePassword { .. } => {
                f.debug_struct("UsernamePassword").finish_non_exhaustive()
            }
        }
    }
}

impl FlightAuthentication {
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken {
            token: Some(token.into()),
        }
    }

    pub fn username_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::UsernamePassword {
            username: Some(username.into()),
            password: Some(password.into()),
            authorization: None,
        }
    }

    /// Effective execution authorization, if the service requires a header.
    pub fn authorization_header(&self) -> Option<&str> {
        match self {
            Self::BearerToken { token } => token.as_deref(),
            Self::UsernamePassword { authorization, .. } => authorization.as_deref(),
        }
    }

    pub(crate) fn validate_credentials(&self) -> Result<()> {
        match self {
            Self::UsernamePassword { username: None, .. } => Err(DataFusionError::Execution(
                "Flight username/password credentials are unresolved".into(),
            )),
            _ => self.validate_execution(),
        }
    }

    pub(crate) fn validate_execution(&self) -> Result<()> {
        if matches!(self, Self::BearerToken { token: None }) {
            return Err(DataFusionError::Execution(
                "Flight bearer credentials are unresolved".into(),
            ));
        }
        if matches!(
            self,
            Self::UsernamePassword {
                username: None,
                authorization: None,
                ..
            }
        ) {
            return Err(DataFusionError::Execution(
                "Flight username/password execution authentication is unresolved".into(),
            ));
        }
        if let Some(value) = self.authorization_header() {
            if value.trim().is_empty() || value.parse::<MetadataValue<Ascii>>().is_err() {
                return Err(DataFusionError::Execution(
                    "invalid Flight authorization header".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Restores complete authentication for decoded plans from caller-owned state.
///
/// Implementations must redact captured credentials from debug output.
pub trait FlightAuthenticationProvider: Send + Sync + fmt::Debug {
    /// Restore the same mode, including its original execution authorization.
    ///
    /// Callers own handshake-token caching. Tickets distinguish sessions for the
    /// same origin. Missing authentication must return an error; do not perform
    /// another handshake or blocking I/O while decoding.
    fn restore(
        &self,
        authentication: &FlightAuthentication,
        origin: &str,
        tickets: &[&[u8]],
    ) -> Result<FlightAuthentication>;
}

#[cfg(test)]
mod tests {
    use super::FlightAuthentication;

    #[test]
    fn authentication_round_trips_only_the_mode_and_redacts_debug() {
        let cases = [
            (
                FlightAuthentication::bearer_token("caller-credential"),
                serde_json::json!({"bearer_token": {}}),
            ),
            (
                FlightAuthentication::UsernamePassword {
                    username: Some("private-user".into()),
                    password: Some("private-password".into()),
                    authorization: Some("server-session-credential".into()),
                },
                serde_json::json!({"username_password": {}}),
            ),
        ];
        for (authentication, expected) in cases {
            assert_eq!(serde_json::to_value(&authentication).unwrap(), expected);
            let restored: FlightAuthentication = serde_json::from_value(expected).unwrap();
            assert_eq!(
                std::mem::discriminant(&restored),
                std::mem::discriminant(&authentication)
            );
            assert!(restored.authorization_header().is_none());
            let debug = format!("{authentication:?}");
            for secret in [
                "caller-credential",
                "private-user",
                "private-password",
                "server-session-credential",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }
}
