// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Default [FlightDriver] for Flight SQL

use std::collections::HashMap;

use arrow_flight::error::{FlightError, Result};
use arrow_flight::flight_service_client::FlightServiceClient;
use arrow_flight::sql::client::FlightSqlServiceClient;
use async_trait::async_trait;
use tonic::transport::Channel;

use crate::{FlightAuthentication, FlightDriver, FlightMetadata, FlightProperties};

pub const QUERY: &str = "flight.sql.query";
pub const HEADER_PREFIX: &str = "flight.sql.header.";

/// Default Flight SQL driver. Requires a [QUERY] to be passed as a table option.
/// Authentication is supplied through [`FlightProperties::with_authentication`].
/// Any additional headers for the `GetFlightInfo` call can be passed as table options
/// using the [HEADER_PREFIX] prefix.
/// If a token is returned by the server with the handshake response, it will be
/// retained as runtime-only authentication in the returned [FlightMetadata].
#[derive(Clone, Debug, Default)]
pub struct FlightSqlDriver {
    persistent_headers: bool,
}

impl FlightSqlDriver {
    pub fn new() -> Self {
        Default::default()
    }

    /// Propagate the static headers configured for Handshake/GetFlightInfo to the subsequent DoGet calls.
    pub fn with_persistent_headers(mut self, persistent_headers: bool) -> Self {
        self.persistent_headers = persistent_headers;
        self
    }

    async fn authenticate_username_password(
        client: &mut FlightSqlServiceClient<Channel>,
        username: &str,
        password: Option<&str>,
    ) -> Result<()> {
        client
            .handshake(username, password.unwrap_or_default())
            .await?;
        Ok(())
    }

    fn authenticate_bearer(client: &mut FlightSqlServiceClient<Channel>, token: &str) {
        client.set_header("authorization", token);
    }
}

#[async_trait]
impl FlightDriver for FlightSqlDriver {
    async fn metadata(
        &self,
        client: FlightServiceClient<Channel>,
        mut properties: FlightProperties,
        options: &HashMap<String, String>,
    ) -> Result<FlightMetadata> {
        let mut client = FlightSqlServiceClient::new_from_inner(client);
        let mut headers = properties.grpc_headers().clone();
        let headers_overlay = options.iter().filter_map(|(key, value)| {
            key.strip_prefix(HEADER_PREFIX)
                .map(|header_name| (header_name.to_owned(), value.to_owned()))
        });
        headers.extend(headers_overlay);
        for (name, value) in &headers {
            client.set_header(name, value)
        }

        let mut authentication = properties.authentication.take();
        if let Some(authentication) = &authentication {
            authentication
                .validate_credentials()
                .map_err(|error| FlightError::ProtocolError(error.to_string()))?;
        }

        let info = match &mut authentication {
            Some(FlightAuthentication::BearerToken { token: Some(token) }) => {
                Self::authenticate_bearer(&mut client, token);
                client.execute(options[QUERY].clone(), None).await?
            }
            Some(FlightAuthentication::UsernamePassword {
                username: Some(username),
                password,
                authorization,
            }) => {
                Self::authenticate_username_password(&mut client, username, password.as_deref())
                    .await?;
                let info = client.execute(options[QUERY].clone(), None).await?;
                *authorization = client.token().map(|token| format!("Bearer {token}"));
                info
            }
            Some(_) => {
                return Err(FlightError::ProtocolError(
                    "Flight authentication credentials are unresolved".into(),
                ));
            }
            None => client.execute(options[QUERY].clone(), None).await?,
        };
        properties.authentication = authentication;

        let partition_headers = if self.persistent_headers {
            headers
        } else {
            HashMap::default()
        };

        let props = properties.with_grpc_headers(partition_headers);
        FlightMetadata::try_new(info, props)
    }
}
