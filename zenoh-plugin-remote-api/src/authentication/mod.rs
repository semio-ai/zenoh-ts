//
// Copyright (c) 2026 Semio
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

//! Authenticated WebSocket clients, each with its own session to the router.
//!
//! A client presents a ticket in the `ticket` query parameter of its WebSocket upgrade
//! request. The upgrade is refused with 401 unless the ticket verifies. Once upgraded, the
//! client gets a client session to the router authenticated by a certificate minted for its
//! principal, so that the router's access control applies to everything it does.

mod certificate;
mod principal;
mod session;
mod ticket;

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    tungstenite::{
        handshake::server::{ErrorResponse, Request, Response},
        http::StatusCode,
        protocol::{frame::coding::CloseCode, CloseFrame},
    },
    WebSocketStream,
};
use zenoh::Session;
use zenoh_result::ZResult;

use self::{
    session::ClientSessionOpener,
    ticket::{TicketRejection, TicketVerifier, VerifiedTicket},
};
use crate::config::Authentication;

/// Admits WebSocket clients that present a valid ticket and opens their sessions.
pub(crate) struct Authenticator {
    tickets: TicketVerifier,
    sessions: ClientSessionOpener,
}

impl Authenticator {
    /// Reads and checks the keys and certificates `config` names.
    pub(crate) fn new(config: &Authentication) -> ZResult<Self> {
        Ok(Authenticator {
            tickets: TicketVerifier::new(&config.ticket)?,
            sessions: ClientSessionOpener::new(&config.client_session)?,
        })
    }

    /// Performs the WebSocket handshake on `stream`, then opens the session of the
    /// principal its ticket names.
    ///
    /// A request without a valid ticket is answered with 401 before any session exists. A
    /// session that cannot be opened closes the WebSocket with an error. Both return `None`
    /// once logged.
    pub(crate) async fn accept<S>(
        &self,
        stream: S,
        remote: SocketAddr,
    ) -> Option<(WebSocketStream<S>, Session)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut verdict: Option<Result<VerifiedTicket, TicketRejection>> = None;
        // The callback's signature is tungstenite's, error response included.
        #[allow(clippy::result_large_err)]
        let check_ticket = |request: &Request, response: Response| {
            let checked = ticket_from_query(request.uri().query())
                .and_then(|ticket| self.tickets.verify(ticket));
            let reply = match checked {
                Ok(_) => Ok(response),
                Err(_) => Err(unauthorized()),
            };
            verdict = Some(checked);
            reply
        };
        let handshake = tokio_tungstenite::accept_hdr_async(stream, check_ticket).await;

        let (mut ws_stream, ticket) = match (handshake, verdict) {
            (Ok(ws_stream), Some(Ok(ticket))) => (ws_stream, ticket),
            (_, Some(Err(rejection))) => {
                tracing::warn!("Refused WebSocket upgrade from {remote}: {rejection}");
                return None;
            }
            (Err(e), _) => {
                tracing::error!("Error during the websocket handshake occurred: {e}");
                return None;
            }
            (Ok(_), None) => {
                // The handshake only completes through the callback above; fail closed.
                tracing::error!("WebSocket from {remote} upgraded without a ticket check");
                return None;
            }
        };

        let principal = &ticket.principal;
        tracing::info!(
            "WebSocket from {remote} authenticated as {principal} (ticket {})",
            ticket.id
        );
        match self.sessions.open(principal).await {
            Ok(session) => Some((ws_stream, session)),
            Err(e) => {
                tracing::error!(
                    "Unable to open a session for {principal} (WebSocket from {remote}): {e}"
                );
                let close = CloseFrame {
                    code: CloseCode::Error,
                    reason: "unable to open a session".into(),
                };
                if let Err(e) = ws_stream.close(Some(close)).await {
                    tracing::debug!("Closing the WebSocket from {remote}: {e}");
                }
                None
            }
        }
    }
}

/// The value of the single `ticket` parameter of an upgrade request's query.
fn ticket_from_query(query: Option<&str>) -> Result<&str, TicketRejection> {
    let mut tickets = query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|parameter| parameter.strip_prefix("ticket="));
    match (tickets.next(), tickets.next()) {
        (None, _) | (Some(""), None) => Err(TicketRejection::Missing),
        (Some(ticket), None) => Ok(ticket),
        // Which of several tickets counts would be ambiguous.
        (Some(_), Some(_)) => Err(TicketRejection::Malformed),
    }
}

fn unauthorized() -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_read_from_the_query() {
        assert_eq!(ticket_from_query(Some("ticket=a.b.c")), Ok("a.b.c"));
        assert_eq!(ticket_from_query(Some("x=1&ticket=a.b.c&y=2")), Ok("a.b.c"));
    }

    #[test]
    fn missing_ticket_is_refused() {
        for query in [None, Some(""), Some("x=1"), Some("ticket"), Some("ticket=")] {
            assert_eq!(
                ticket_from_query(query),
                Err(TicketRejection::Missing),
                "{query:?}"
            );
        }
        assert_eq!(
            ticket_from_query(Some("tickets=a.b.c")),
            Err(TicketRejection::Missing)
        );
    }

    #[test]
    fn several_tickets_are_refused() {
        assert_eq!(
            ticket_from_query(Some("ticket=a.b.c&ticket=d.e.f")),
            Err(TicketRejection::Malformed)
        );
    }
}
