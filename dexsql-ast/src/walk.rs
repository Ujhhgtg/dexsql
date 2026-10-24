//! Token-stream walker matching the reference `dexsql-ast/src/walk.rs`
//! module boundary.  The expression-level parser is provided by the
//! workspace's sqlparser integration; this module exposes the token cursor
//! utilities the front-end layers share.

use crate::token::{Token, TokenKind};

/// Cursor over a statement's tokens used by the classifier helpers.
pub struct TokenCursor<'a> {
    tokens: &'a [Token],
    sql: &'a str,
    pos: usize,
}

impl<'a> TokenCursor<'a> {
    pub fn new(tokens: &'a [Token], sql: &'a str) -> Self {
        Self {
            tokens,
            sql,
            pos: 0,
        }
    }

    pub fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    pub fn peek_keyword(&self) -> Option<&'a str> {
        self.peek().and_then(|token| token.keyword())
    }

    pub fn next(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(token)
    }

    pub fn eat_keyword(&mut self, keyword: &str) -> bool {
        if self.peek_keyword() == Some(keyword) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.peek().is_some_and(|token| &token.kind == kind) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub fn exhausted(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    pub fn sql(&self) -> &'a str {
        self.sql
    }
}
