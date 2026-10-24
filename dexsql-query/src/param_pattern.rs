//! Positional parameter-type pattern matching for the `methods` relation.
//!
//! DexKit's `ParametersMatcher` accepts a fixed-length parameter list where an
//! entry can be a literal type or `null` (matches exactly one parameter of any
//! type). The SQL engine exposes the same predicate as a boolean scalar
//! function used in a WHERE clause:
//!
//! `param_types_match(<alias>.param_descriptors, '<pattern>')`
//!
//! `param_descriptors` is the methods/protos column: DEX type descriptors
//! joined by `,` in declaration order (empty string for zero parameters).
//! `pattern` is a `,`-separated list of the same descriptors, except that a
//! `?` token matches exactly one parameter of any type:
//!
//! * arity is exact: the token count must equal the parameter count;
//! * `''` (empty pattern) means "exactly zero parameters";
//! * descriptors are compared case-sensitively;
//! * a malformed pattern (an empty token, or `?` embedded in a token) matches
//!   nothing rather than raising an error, mirroring the engine's general
//!   WHERE-evaluation behavior and keeping the fast path and the generic path
//!   identical;
//! * `NULL` arguments propagate to `NULL` (a WHERE context treats that as false).
//!
//! The canonical shape emitted by the query DSL/extractor is the bare function
//! call in a top-level AND conjunct (no `= 1` wrapper). The `= 1` comparison is
//! also accepted by the descriptor-lookup fast path for robustness.
//!
//! `param_count` ranges use the inclusive two-comparison form
//! `<alias>.param_count >= MIN AND <alias>.param_count <= MAX` (strict `>`/`<`
//! bounds are also recognized and normalized for integers). When MIN == MAX the
//! existing `param_count = N` equality form stays canonical.

/// One token of a compiled parameter-type pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParamPatternToken {
    /// Matches exactly one parameter of any type.
    Wildcard,
    /// Matches exactly one parameter whose descriptor equals this string.
    Exact(String),
}

/// Compiled form of a `param_types_match` pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParamPattern {
    /// `None` for a malformed pattern, which never matches.
    tokens: Option<Vec<ParamPatternToken>>,
}

impl ParamPattern {
    /// Compile one pattern string. Malformed patterns compile to a matcher that
    /// never matches (documented `param_types_match` behaviour).
    pub(crate) fn parse(pattern: &str) -> Self {
        if pattern.is_empty() {
            return Self {
                tokens: Some(Vec::new()),
            };
        }
        let mut tokens = Vec::new();
        for token in pattern.split(',') {
            if token.is_empty() || (token.contains('?') && token != "?") {
                return Self { tokens: None };
            }
            tokens.push(if token == "?" {
                ParamPatternToken::Wildcard
            } else {
                ParamPatternToken::Exact(token.to_owned())
            });
        }
        Self {
            tokens: Some(tokens),
        }
    }

    /// Match against the `methods.param_descriptors` text representation.
    pub(crate) fn matches_descriptors(&self, descriptors: &str) -> bool {
        let Some(tokens) = &self.tokens else {
            return false;
        };
        // The descriptor column uses the empty string for "no parameters";
        // splitting it would produce one empty token.
        if descriptors.is_empty() {
            return tokens.is_empty();
        }
        if tokens.is_empty() {
            return false;
        }
        let mut parts = descriptors.split(',');
        for token in tokens {
            let Some(part) = parts.next() else {
                return false;
            };
            if let ParamPatternToken::Exact(expected) = token {
                if part != expected {
                    return false;
                }
            }
        }
        parts.next().is_none()
    }

    /// Match against per-file proto parameters without materializing the
    /// descriptor string (the descriptor-lookup fast path).
    pub(crate) fn matches_params<'a>(
        &self,
        count: usize,
        param: impl Fn(usize) -> &'a str,
    ) -> bool {
        let Some(tokens) = &self.tokens else {
            return false;
        };
        if tokens.len() != count {
            return false;
        }
        tokens.iter().enumerate().all(|(index, token)| match token {
            ParamPatternToken::Wildcard => true,
            ParamPatternToken::Exact(expected) => param(index) == expected,
        })
    }
}

/// Generic-evaluator entry point for `param_types_match`.
pub(crate) fn param_types_match_text(descriptors: &str, pattern: &str) -> bool {
    ParamPattern::parse(pattern).matches_descriptors(descriptors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(descriptors: &str, pattern: &str) -> bool {
        param_types_match_text(descriptors, pattern)
    }

    #[test]
    fn empty_pattern_matches_only_zero_parameters() {
        assert!(matches("", ""));
        assert!(!matches("I", ""));
        assert!(!matches("", "I"));
    }

    #[test]
    fn exact_descriptors_match_case_sensitively() {
        assert!(matches("I", "I"));
        assert!(matches("Ljava/lang/String;,[I", "Ljava/lang/String;,[I"));
        assert!(!matches("Ljava/lang/String;", "Ljava/lang/String"));
        assert!(!matches("I", "i"));
        assert!(!matches("Ljava/lang/String;", "Ljava/lang/String; "));
    }

    #[test]
    fn wildcards_match_exactly_one_parameter() {
        // Wildcard at the end.
        assert!(matches("I,Ljava/lang/String;", "I,?"));
        // Wildcard at the start.
        assert!(matches("I,Ljava/lang/String;", "?,Ljava/lang/String;"));
        // Wildcard in the middle.
        assert!(matches(
            "I,J,Ljava/lang/String;,[I",
            "I,?,Ljava/lang/String;,[I"
        ));
        // Wildcards at both ends.
        assert!(matches("I,J,[I", "?,?,?"));
        // A wildcard also matches array and object descriptors.
        assert!(matches("[I", "?"));
        assert!(matches("Lx/y;", "?"));
        assert!(matches("[I,Lx/y;", "[I,?"));
        assert!(matches("Lx/y;,[I", "?,[I"));
        assert!(!matches("Lx/y;,[I", "?,[J"));
        assert!(matches("Lx/y;,[I", "?,?"));
    }

    #[test]
    fn arrays_and_objects_match_as_literal_tokens() {
        assert!(matches(
            "[I,Ljava/lang/String;,[[J",
            "[I,Ljava/lang/String;,[[J"
        ));
        assert!(matches("[[I", "[[I"));
        assert!(!matches("[[I", "[I"));
        assert!(matches(
            "Landroid/content/Context;",
            "Landroid/content/Context;"
        ));
    }

    #[test]
    fn arity_is_exact() {
        assert!(!matches("I,J", "I"));
        assert!(!matches("I", "I,J"));
        assert!(!matches("I,J,K", "I,?"));
        assert!(matches("I,J,K", "I,?,?"));
        assert!(!matches("", "?"));
        assert!(!matches("I", "?,?"));
    }

    #[test]
    fn wildcard_only_patterns() {
        assert!(matches("I", "?"));
        assert!(matches("[I,Lx;", "?,?"));
        assert!(!matches("", "?"));
        assert!(!matches("I,J", "?"));
    }

    #[test]
    fn malformed_patterns_match_nothing() {
        for pattern in [",", "I,", ",I", "I,,J", "??", "Lx?;"] {
            assert!(!matches("", pattern), "{pattern:?}");
            assert!(!matches("I,J", pattern), "{pattern:?}");
        }
    }

    #[test]
    fn compiled_pattern_reuses_parsing() {
        let pattern = ParamPattern::parse("I,?,J");
        assert!(pattern.matches_descriptors("I,Lx;,J"));
        assert!(pattern.matches_params(3, |index| ["I", "[I", "J"][index]));
        assert!(!pattern.matches_params(2, |index| ["I", "J"][index]));
        let malformed = ParamPattern::parse("I,");
        assert!(!malformed.matches_descriptors("I,"));
        assert!(!malformed.matches_params(2, |index| ["I", ""][index]));
    }
}
