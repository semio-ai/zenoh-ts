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

use std::fmt;

/// Characters that cannot appear in a single key-expression chunk: the separator, the
/// wildcard, the DSL marker and the two reserved characters.
const FORBIDDEN: [char; 5] = ['/', '*', '$', '#', '?'];

/// The identity a WebSocket client acts as: the Common Name of its client certificate,
/// which the router's access control matches.
///
/// It is a valid single key-expression chunk, so that rules and key expressions can embed
/// it as one segment without it matching or spanning anything else. It holds no control
/// characters either, which have no place in a certificate name and would forge log lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Principal(String);

impl Principal {
    /// The principal `prefix` + `subject`, or `None` when the subject is empty or the result
    /// is not a single key-expression chunk or holds a control character.
    pub(crate) fn new(prefix: &str, subject: &str) -> Option<Self> {
        if subject.is_empty() {
            return None;
        }
        let principal = format!("{prefix}{subject}");
        is_valid(&principal).then_some(Principal(principal))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `prefix` can start a principal: it holds none of the characters a principal
/// forbids. It may be empty.
pub(crate) fn is_valid_prefix(prefix: &str) -> bool {
    !prefix.contains(is_forbidden)
}

fn is_valid(principal: &str) -> bool {
    !principal.is_empty() && !principal.contains(is_forbidden)
}

fn is_forbidden(c: char) -> bool {
    FORBIDDEN.contains(&c) || c.is_control()
}

#[cfg(test)]
mod tests {
    use zenoh::key_expr::KeyExpr;

    use super::*;

    #[test]
    fn principal_is_prefix_and_subject() {
        let principal = Principal::new("u:", "Xy12abc").unwrap();
        assert_eq!(principal.as_str(), "u:Xy12abc");
        assert_eq!(principal.to_string(), "u:Xy12abc");
    }

    #[test]
    fn principal_is_a_single_key_expression_chunk() {
        let principal = Principal::new("u:", "Xy12abc").unwrap();
        let key = KeyExpr::try_from(format!("state/{principal}/pose")).unwrap();
        assert_eq!(key.as_str().split('/').nth(1), Some(principal.as_str()));
    }

    #[test]
    fn subject_with_a_forbidden_character_is_refused() {
        for subject in [
            "a/b", "*", "**", "a*", "$*", "a$b", "a#b", "a?b", "/", "a\nb", "a\rb", "\u{7f}",
            "\u{85}",
        ] {
            assert_eq!(Principal::new("u:", subject), None, "{subject:?}");
        }
    }

    #[test]
    fn empty_subject_is_refused() {
        assert_eq!(Principal::new("u:", ""), None);
        assert_eq!(Principal::new("", ""), None);
    }

    #[test]
    fn prefix_may_be_empty_but_not_forbidden() {
        assert!(is_valid_prefix(""));
        assert!(is_valid_prefix("u:"));
        assert!(!is_valid_prefix("u/"));
        assert!(!is_valid_prefix("u*"));
        assert!(!is_valid_prefix("u\n"));
        assert_eq!(Principal::new("", "alice").unwrap().as_str(), "alice");
    }
}
