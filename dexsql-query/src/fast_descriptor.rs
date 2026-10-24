//! Index-driven execution for descriptor-lookup SQL.
//!
//! WeKit's DexSQL workload consists of descriptor lookups: find the single
//! method/class/field descriptor that matches a conjunction of string/number
//! literals and relation metadata predicates. The generic relation executor is
//! correct but materialises complete relations as row hash maps, which is
//! orders of magnitude slower and more memory hungry than the reference
//! engine. This module recognises the canonical lookup shapes emitted by
//! WeKit's SQL DSL and answers them directly from the dataset metadata
//! indexes. Anything that does not match one of these shapes returns None so
//! the generic executor remains the fallback.

use std::collections::HashSet;

use dexsql_cache::{Dataset, DexFile};
use rayon::prelude::*;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, JoinConstraint,
    JoinOperator, Select, SelectItem, SetExpr, TableFactor, UnaryOperator, Value, ValueWithSpan,
};

use crate::param_pattern::ParamPattern;
use crate::QueryResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LikeMode {
    Equal,
    Contains,
    Prefix,
    Suffix,
}

#[derive(Debug, Clone)]
struct StringNeed {
    mode: LikeMode,
    value: String,
    /// LIKE comparisons follow SQLite semantics (ASCII case folding); equality
    /// predicates stay case sensitive.
    case_insensitive: bool,
}

#[derive(Debug, Clone, Default)]
struct MethodFilter {
    strings: Vec<StringNeed>,
    numbers: Vec<i64>,
    doubles: Vec<f64>,
    opcode_count_min: Option<i64>,
    opcode_count_max: Option<i64>,
    names: Vec<String>,
    classes: Vec<String>,
    class_likes: Vec<StringNeed>,
    returns: Vec<StringNeed>,
    param_counts: Vec<i64>,
    param_descriptors: Vec<String>,
    /// positional parameter patterns, all of which must match.
    param_patterns: Vec<ParamPattern>,
    /// ANY-of parameter patterns (DexKit anyOf alternatives).
    param_pattern_any: Vec<ParamPattern>,
    /// Inclusive lower/upper bounds for param_count ranges (all must hold).
    param_count_min: Vec<i64>,
    param_count_max: Vec<i64>,
    /// Bitwise access-flag conditions: (mask, expected).
    flags: Vec<(i64, i64)>,
    /// Rejected declaring-class descriptor prefixes (excludePackages).
    excluded_class_likes: Vec<StringNeed>,
}

impl MethodFilter {
    fn is_empty(&self) -> bool {
        self.strings.is_empty()
            && self.numbers.is_empty()
            && self.doubles.is_empty()
            && self.opcode_count_min.is_none()
            && self.opcode_count_max.is_none()
            && self.names.is_empty()
            && self.classes.is_empty()
            && self.class_likes.is_empty()
            && self.returns.is_empty()
            && self.param_counts.is_empty()
            && self.param_descriptors.is_empty()
            && self.param_patterns.is_empty()
            && self.param_pattern_any.is_empty()
            && self.param_count_min.is_empty()
            && self.param_count_max.is_empty()
            && self.flags.is_empty()
            && self.excluded_class_likes.is_empty()
    }

    fn merge(&mut self, other: MethodFilter) {
        self.strings.extend(other.strings);
        self.numbers.extend(other.numbers);
        self.doubles.extend(other.doubles);
        self.opcode_count_min = self.opcode_count_min.max(other.opcode_count_min);
        self.opcode_count_max = self.opcode_count_max.min(other.opcode_count_max);
        self.names.extend(other.names);
        self.classes.extend(other.classes);
        self.class_likes.extend(other.class_likes);
        self.returns.extend(other.returns);
        self.param_counts.extend(other.param_counts);
        self.param_descriptors.extend(other.param_descriptors);
        self.param_patterns.extend(other.param_patterns);
        self.param_pattern_any.extend(other.param_pattern_any);
        self.param_count_min.extend(other.param_count_min);
        self.param_count_max.extend(other.param_count_max);
        self.flags.extend(other.flags);
        self.excluded_class_likes.extend(other.excluded_class_likes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Method,
    Constructor,
    Class,
    BareClass,
    Field,
}

#[derive(Debug, Clone)]
struct Factor {
    alias: String,
    table: String,
}

#[derive(Debug, Clone)]
enum PredKind {
    Eq,
    Like,
    /// Case-sensitive substring/prefix/suffix predicates expressed with
    /// instr()/substr() in the canonical SQL (DexKit StringMatcher semantics).
    Contains,
    Prefix,
    Suffix,
    /// Bitwise flags condition: (column & mask) == expected.
    Flags(i64),
    /// param_types_match(column, pattern): positional parameter pattern.
    ParamTypesMatch,
    /// param_types_match alternative inside an OR group (DexKit anyOf).
    ParamTypesMatchAny,
    /// Inclusive lower/upper bound on an integer column (param_count ranges).
    Gte,
    Lte,
    /// Negated instr() substring predicate: NOT (instr(column, literal) > 0).
    NotContains,
    /// Negated instr() prefix predicate: NOT (instr(column, literal) = 1).
    NotPrefix,
}

#[derive(Debug, Clone, PartialEq)]
enum Scalar {
    Text(String),
    Int(i64),
    Double(f64),
}

#[derive(Debug, Clone)]
struct Pred {
    alias: Option<String>,
    column: String,
    kind: PredKind,
    value: Scalar,
    escape: Option<char>,
}

impl Pred {
    fn text(&self) -> Option<&str> {
        match &self.value {
            Scalar::Text(text) => Some(text.as_str()),
            Scalar::Int(_) | Scalar::Double(_) => None,
        }
    }

    fn int(&self) -> Option<i64> {
        match &self.value {
            Scalar::Int(value) => Some(*value),
            Scalar::Text(_) | Scalar::Double(_) => None,
        }
    }

    fn double(&self) -> Option<f64> {
        match &self.value {
            Scalar::Double(value) => Some(*value),
            Scalar::Int(value) => Some(*value as f64),
            Scalar::Text(_) => None,
        }
    }
}

fn table_factor(factor: &TableFactor) -> Option<(String, String)> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return None;
    };
    if args.is_some() {
        return None;
    }
    let table = name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.to_ascii_lowercase())?;
    let alias = alias
        .as_ref()
        .map(|value| value.name.value.clone())
        .unwrap_or_else(|| table.clone());
    Some((alias, table))
}

fn column_expr(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Identifier(ident) => Some((None, ident.value.to_ascii_lowercase())),
        Expr::CompoundIdentifier(idents) => {
            if idents.len() != 2 {
                return None;
            }
            Some((
                Some(idents[0].value.clone()),
                idents[1].value.to_ascii_lowercase(),
            ))
        }
        _ => None,
    }
}

fn scalar_value(value: &ValueWithSpan) -> Option<Scalar> {
    match &value.value {
        Value::SingleQuotedString(text)
        | Value::DoubleQuotedString(text)
        | Value::EscapedStringLiteral(text)
        | Value::NationalStringLiteral(text) => Some(Scalar::Text(text.clone())),
        Value::Number(number, _) => number
            .parse::<i64>()
            .map(Scalar::Int)
            .or_else(|_| number.parse::<f64>().map(Scalar::Double))
            .ok(),
        _ => None,
    }
}

/// Parse the four plain LIKE forms into a mode, honouring an optional ESCAPE
/// character. Returns None for any other wildcard placement so the generic
/// matcher remains authoritative.
fn parse_like_pattern(pattern: &str, escape: Option<char>) -> Option<StringNeed> {
    #[derive(Clone, Copy, PartialEq)]
    enum Token {
        AnySeq,
        AnyOne,
        Lit,
    }
    let mut tokens: Vec<(Token, Option<char>)> = Vec::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            let literal = chars.next()?;
            tokens.push((Token::Lit, Some(literal)));
            continue;
        }
        match ch {
            '%' => tokens.push((Token::AnySeq, None)),
            '_' => tokens.push((Token::AnyOne, None)),
            literal => tokens.push((Token::Lit, Some(literal))),
        }
    }
    let mut leading = false;
    let mut trailing = false;
    let mut value = String::new();
    let mut index = 0;
    if matches!(tokens.first(), Some((Token::AnySeq, _))) {
        leading = true;
        index += 1;
    }
    if tokens.len() > index && matches!(tokens.last(), Some((Token::AnySeq, _))) {
        trailing = true;
    } else if leading && index == tokens.len() {
        return None;
    }
    let end = if trailing {
        tokens.len() - 1
    } else {
        tokens.len()
    };
    for (token, literal) in &tokens[index..end] {
        match token {
            Token::Lit => value.push((*literal)?),
            _ => return None,
        }
    }
    if value.is_empty() {
        return None;
    }
    if !leading && !trailing && index > 0 {
        return None;
    }
    let mode = match (leading, trailing) {
        (false, false) => LikeMode::Equal,
        (true, false) => LikeMode::Suffix,
        (false, true) => LikeMode::Prefix,
        (true, true) => LikeMode::Contains,
    };
    Some(StringNeed {
        mode,
        value,
        case_insensitive: true,
    })
}

fn flatten_and<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Nested(inner) => flatten_and(inner, out),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
            ..
        } => {
            flatten_and(left, out);
            flatten_and(right, out);
        }
        other => out.push(other),
    }
}

const SCOPE_COLUMNS: &[&str] = &[
    "file_id",
    "method_idx",
    "class_idx",
    "field_idx",
    "string_pool_id",
];

/// Collect the OR-grouped instr prefix predicates used by multi-package searchPackages.
fn collect_or_instr_predicates(expr: &Expr, preds: &mut Vec<Pred>) -> Option<()> {
    let mut expr = expr;
    while let Expr::Nested(inner) = expr {
        expr = inner.as_ref();
    }
    if let Expr::BinaryOp {
        left,
        op: BinaryOperator::Or,
        right,
        ..
    } = expr
    {
        collect_or_instr_predicates(left, preds)?;
        collect_or_instr_predicates(right, preds)?;
        return Some(());
    }
    if let Expr::BinaryOp {
        left, op, right, ..
    } = expr
    {
        if matches!(op, BinaryOperator::Eq) {
            if let Some(pred) = param_types_match_predicate(left) {
                if function_literal_int(right) == Some(1) {
                    preds.push(Pred {
                        alias: pred.alias,
                        column: pred.column,
                        kind: PredKind::ParamTypesMatchAny,
                        value: pred.value,
                        escape: None,
                    });
                    return Some(());
                }
            }
        }
        let pred = string_function_predicate(left, right, op)?;
        if !matches!(pred.kind, PredKind::Prefix) {
            return None;
        }
        preds.push(pred);
        return Some(());
    }
    None
}

fn parse_predicates(select: &Select) -> Option<(Vec<Pred>, Vec<(String, String)>)> {
    let mut conjuncts = Vec::new();
    if let Some(selection) = &select.selection {
        flatten_and(selection, &mut conjuncts);
    }
    let mut preds = Vec::with_capacity(conjuncts.len());
    let mut distinct = Vec::new();
    for conjunct in conjuncts {
        match conjunct {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
                ..
            } => {
                if let Some((alias, mask, expected)) = bitwise_flags_predicate(left, right) {
                    preds.push(Pred {
                        alias: Some(alias),
                        column: "access_flags".to_owned(),
                        kind: PredKind::Flags(mask),
                        value: Scalar::Int(expected),
                        escape: None,
                    });
                    continue;
                }
                if let Some(pred) = string_function_predicate(left, right, &BinaryOperator::Eq) {
                    preds.push(pred);
                    continue;
                }
                if let Some(pred) = param_types_match_predicate(left) {
                    // Only "= 1" keeps the boolean function's truth value; any
                    // other comparison falls back to the generic executor.
                    if function_literal_int(right) == Some(1) {
                        preds.push(pred);
                        continue;
                    }
                    return None;
                }
                let (alias, column) = column_expr(left)?;
                if let Expr::Value(value) = right.as_ref() {
                    preds.push(Pred {
                        alias,
                        column,
                        kind: PredKind::Eq,
                        value: scalar_value(value)?,
                        escape: None,
                    });
                    continue;
                }
                let (right_alias, right_column) = column_expr(right)?;
                let scoped = SCOPE_COLUMNS.contains(&column.as_str())
                    && column == right_column
                    && alias != right_alias;
                if scoped {
                    continue;
                }
                return None;
            }
            Expr::BinaryOp {
                left,
                op:
                    op @ (BinaryOperator::Gt
                    | BinaryOperator::GtEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq),
                right,
                ..
            } => {
                if let Some(pred) = string_function_predicate(left, right, op) {
                    preds.push(pred);
                } else {
                    preds.push(numeric_bound_predicate(left, op, right)?);
                }
            }
            Expr::Like {
                negated: false,
                expr,
                pattern,
                escape_char,
                ..
            } => {
                let (alias, column) = column_expr(expr)?;
                let Expr::Value(value) = pattern.as_ref() else {
                    return None;
                };
                let escape = match escape_char.as_ref() {
                    None => None,
                    Some(escape_expr) => escape_char_from_expr(escape_expr)?,
                };
                preds.push(Pred {
                    alias,
                    column,
                    kind: PredKind::Like,
                    value: scalar_value(value)?,
                    escape,
                });
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr,
            } => {
                // Canonical injective-methods condition:
                //   NOT (cmA.file_id = cmB.file_id AND cmA.method_idx = cmB.method_idx)
                let Expr::Nested(inner) = expr.as_ref() else {
                    return None;
                };
                if let Expr::BinaryOp {
                    left, op, right, ..
                } = inner.as_ref()
                {
                    // Negated descriptor predicates (DexKit excludePackages):
                    //   NOT (instr(class_descriptor, 'Lpkg/') = 1)
                    if let Some(pred) = string_function_predicate(left, right, op) {
                        let kind = match pred.kind {
                            PredKind::Prefix => PredKind::NotPrefix,
                            PredKind::Contains => PredKind::NotContains,
                            _ => return None,
                        };
                        preds.push(Pred {
                            alias: pred.alias,
                            column: pred.column,
                            kind,
                            value: pred.value,
                            escape: None,
                        });
                        continue;
                    }
                    let Expr::BinaryOp {
                        op: BinaryOperator::And,
                        ..
                    } = inner.as_ref()
                    else {
                        return None;
                    };
                    let Expr::BinaryOp {
                        left,
                        op: BinaryOperator::And,
                        right,
                        ..
                    } = inner.as_ref()
                    else {
                        return None;
                    };
                    let pair = distinct_pair(left, right)?;
                    distinct.push(pair);
                    continue;
                }
                return None;
            }
            Expr::Nested(inner) => {
                // Canonical searchPackages group:
                //   (instr(col, 'Lpkg1/') = 1 OR instr(col, 'Lpkg2/') = 1)
                // or a single parenthesized instr predicate.
                collect_or_instr_predicates(inner, &mut preds)?;
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Or,
                right,
                ..
            } => {
                // sqlparser may strip the parentheses around an OR group inside an AND chain.
                collect_or_instr_predicates(left, &mut preds)?;
                collect_or_instr_predicates(right, &mut preds)?;
            }
            Expr::Function(function) => {
                preds.push(param_types_match_function_predicate(function)?);
            }
            _ => return None,
        }
    }
    Some((preds, distinct))
}

fn distinct_pair(left: &Expr, right: &Expr) -> Option<(String, String)> {
    fn eq_aliases(expr: &Expr) -> Option<((String, String), (String, String))> {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
            ..
        } = expr
        else {
            return None;
        };
        let (left_alias, left_column) = column_expr(left)?;
        let (right_alias, right_column) = column_expr(right)?;
        Some(((left_alias?, left_column), (right_alias?, right_column)))
    }
    let ((left_alias_a, left_column_a), (right_alias_a, right_column_a)) = eq_aliases(left)?;
    let ((left_alias_b, left_column_b), (right_alias_b, right_column_b)) = eq_aliases(right)?;
    let same_aliases = left_alias_a == left_alias_b && right_alias_a == right_alias_b;
    let file_columns = left_column_a == "file_id" && right_column_a == "file_id";
    // Injective method units are distinct by method_idx, declared-field units by field_idx,
    // and class-interface units by ordinal.
    let identity_columns = (left_column_b == "method_idx" && right_column_b == "method_idx")
        || (left_column_b == "field_idx" && right_column_b == "field_idx")
        || (left_column_b == "ordinal" && right_column_b == "ordinal");
    if !same_aliases || !file_columns || !identity_columns {
        return None;
    }
    if left_alias_a == right_alias_a {
        return None;
    }
    Some((left_alias_a, right_alias_a))
}

type JoinColumns = ((Option<String>, String), (Option<String>, String));

fn join_on_columns(operator: &JoinOperator) -> Option<JoinColumns> {
    let constraint = match operator {
        JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => c,
        _ => return None,
    };
    let JoinConstraint::On(expr) = constraint else {
        return None;
    };
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
        ..
    } = expr
    else {
        return None;
    };
    Some((column_expr(left)?, column_expr(right)?))
}

fn table_for<'a>(factors: &'a [Factor], alias: &str) -> Option<&'a str> {
    factors
        .iter()
        .find(|factor| factor.alias == alias)
        .map(|factor| factor.table.as_str())
}

fn is_method_string_join(columns: &JoinColumns) -> bool {
    (columns.0 .1 == "method" && columns.1 .1 == "descriptor")
        || (columns.0 .1 == "descriptor" && columns.1 .1 == "method")
}

fn is_class_unit_join(columns: &JoinColumns) -> bool {
    columns.0 .1 == "class_descriptor" && columns.1 .1 == "class_descriptor"
}

fn is_class_join(columns: &JoinColumns) -> bool {
    (columns.0 .1 == "descriptor" && columns.1 .1 == "class_descriptor")
        || (columns.0 .1 == "class_descriptor" && columns.1 .1 == "descriptor")
}

fn is_field_access_join(columns: &JoinColumns) -> bool {
    (columns.0 .1 == "field" && columns.1 .1 == "descriptor")
        || (columns.0 .1 == "descriptor" && columns.1 .1 == "field")
}

fn is_method_access_join(columns: &JoinColumns) -> bool {
    (columns.0 .1 == "descriptor" && columns.1 .1 == "method")
        || (columns.0 .1 == "method" && columns.1 .1 == "descriptor")
}

fn ascii_contains_ci(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn plain_like_match(value: &str, need: &StringNeed) -> bool {
    match need.mode {
        LikeMode::Equal => {
            if need.case_insensitive {
                value.eq_ignore_ascii_case(&need.value)
            } else {
                value == need.value
            }
        }
        LikeMode::Contains => {
            if need.case_insensitive {
                ascii_contains_ci(value, &need.value)
            } else {
                value.contains(need.value.as_str())
            }
        }
        LikeMode::Prefix => {
            if need.case_insensitive {
                value
                    .as_bytes()
                    .get(..need.value.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(need.value.as_bytes()))
            } else {
                value.starts_with(need.value.as_str())
            }
        }
        LikeMode::Suffix => {
            if need.case_insensitive {
                value
                    .as_bytes()
                    .get(value.len().saturating_sub(need.value.len())..)
                    .is_some_and(|tail| {
                        tail.len() == need.value.len()
                            && tail.eq_ignore_ascii_case(need.value.as_bytes())
                    })
            } else {
                value.ends_with(need.value.as_str())
            }
        }
    }
}

fn like_predicate_matches(value: &str, pattern: &str) -> Option<bool> {
    parse_like_pattern(pattern, None).map(|need| plain_like_match(value, &need))
}

fn escape_char_from_expr(expr: &Expr) -> Option<Option<char>> {
    let mut expr = expr;
    while let Expr::Nested(inner) = expr {
        expr = inner.as_ref();
    }
    let Expr::Value(value) = expr else {
        return None;
    };
    let Scalar::Text(text) = scalar_value(value)? else {
        return None;
    };
    let mut chars = text.chars();
    let escape = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    Some(Some(escape))
}

fn function_literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Value(value) => match scalar_value(value)? {
            Scalar::Text(text) => Some(text),
            Scalar::Int(value) => Some(value.to_string()),
            Scalar::Double(value) => Some(value.to_string()),
        },
        Expr::Nested(inner) => function_literal_text(inner),
        _ => None,
    }
}

fn function_literal_int(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Value(value) => match scalar_value(value)? {
            Scalar::Int(value) => Some(value),
            Scalar::Text(_) | Scalar::Double(_) => None,
        },
        Expr::Nested(inner) => function_literal_int(inner),
        _ => None,
    }
}

fn negative_start_length(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => function_literal_int(expr),
        Expr::Nested(inner) => negative_start_length(inner),
        _ => None,
    }
}

/// Recognises the canonical case-sensitive string predicates:
///   instr(column, 'literal') > 0    -> contains
///   instr(column, 'literal') = 1    -> prefix
///   substr(column, -N) = 'literal'  -> suffix (N is the literal length)
fn string_function_predicate(left: &Expr, right: &Expr, op: &BinaryOperator) -> Option<Pred> {
    let mut left = left;
    while let Expr::Nested(inner) = left {
        left = inner.as_ref();
    }
    if let Expr::Function(function) = left {
        let name = function
            .name
            .0
            .last()
            .map(|part| part.to_string().to_ascii_lowercase())?;
        if name != "instr" {
            return None;
        }
        let FunctionArguments::List(arguments) = &function.args else {
            return None;
        };
        if arguments.args.len() != 2 {
            return None;
        }
        let FunctionArg::Unnamed(FunctionArgExpr::Expr(column_node)) = &arguments.args[0] else {
            return None;
        };
        let FunctionArg::Unnamed(FunctionArgExpr::Expr(literal_expr)) = &arguments.args[1] else {
            return None;
        };
        let (alias, column) = column_expr(column_node)?;
        let value = function_literal_text(literal_expr)?;
        let kind = match (op, function_literal_int(right)?) {
            (BinaryOperator::Gt, 0) => PredKind::Contains,
            (BinaryOperator::Eq, 1) => PredKind::Prefix,
            _ => return None,
        };
        return Some(Pred {
            alias,
            column,
            kind,
            value: Scalar::Text(value),
            escape: None,
        });
    }
    if let Expr::Substring {
        expr,
        substring_from: Some(from),
        substring_for: None,
        ..
    } = left
    {
        let (alias, column) = column_expr(expr)?;
        let value = function_literal_text(right)?;
        if negative_start_length(from)? != value.chars().count() as i64 {
            return None;
        }
        return Some(Pred {
            alias,
            column,
            kind: PredKind::Suffix,
            value: Scalar::Text(value),
            escape: None,
        });
    }
    None
}

/// Recognises the param-pattern predicate:
///   param_types_match(<column>.param_descriptors, '<pattern>')
fn param_types_match_predicate(expr: &Expr) -> Option<Pred> {
    let mut expr = expr;
    while let Expr::Nested(inner) = expr {
        expr = inner.as_ref();
    }
    let Expr::Function(function) = expr else {
        return None;
    };
    param_types_match_function_predicate(function)
}

fn param_types_match_function_predicate(function: &sqlparser::ast::Function) -> Option<Pred> {
    let name = function
        .name
        .0
        .last()
        .map(|part| part.to_string().to_ascii_lowercase())?;
    if name != "param_types_match" {
        return None;
    }
    let FunctionArguments::List(arguments) = &function.args else {
        return None;
    };
    if arguments.args.len() != 2 {
        return None;
    }
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(column_node)) = &arguments.args[0] else {
        return None;
    };
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(pattern_node)) = &arguments.args[1] else {
        return None;
    };
    let (alias, column) = column_expr(column_node)?;
    if column != "param_descriptors" {
        return None;
    }
    let pattern = function_literal_text(pattern_node)?;
    Some(Pred {
        alias,
        column,
        kind: PredKind::ParamTypesMatch,
        value: Scalar::Text(pattern),
        escape: None,
    })
}

/// Recognises inclusive integer bounds used by the canonical paramCount range
/// form: `param_count >= MIN AND param_count <= MAX`. Strict bounds are
/// normalised to inclusive integers (`> v` becomes `>= v+1`).
fn numeric_bound_predicate(left: &Expr, op: &BinaryOperator, right: &Expr) -> Option<Pred> {
    let (alias, column) = column_expr(left)?;
    let value = function_literal_int(right)?;
    let (kind, bound) = match op {
        BinaryOperator::Gt => (PredKind::Gte, value.checked_add(1)?),
        BinaryOperator::GtEq => (PredKind::Gte, value),
        BinaryOperator::Lt => (PredKind::Lte, value.checked_sub(1)?),
        BinaryOperator::LtEq => (PredKind::Lte, value),
        _ => return None,
    };
    Some(Pred {
        alias,
        column,
        kind,
        value: Scalar::Int(bound),
        escape: None,
    })
}

fn class_descriptor_need(pred: &Pred) -> Option<StringNeed> {
    match pred.kind {
        PredKind::NotContains | PredKind::NotPrefix => None,
        PredKind::Like => parse_like_pattern(pred.text()?, pred.escape),
        PredKind::Prefix => Some(StringNeed {
            mode: LikeMode::Prefix,
            value: pred.text()?.to_owned(),
            case_insensitive: false,
        }),
        PredKind::Contains => Some(StringNeed {
            mode: LikeMode::Contains,
            value: pred.text()?.to_owned(),
            case_insensitive: false,
        }),
        PredKind::Suffix => Some(StringNeed {
            mode: LikeMode::Suffix,
            value: pred.text()?.to_owned(),
            case_insensitive: false,
        }),
        PredKind::Eq
        | PredKind::Flags(_)
        | PredKind::ParamTypesMatch
        | PredKind::ParamTypesMatchAny
        | PredKind::Gte
        | PredKind::Lte => None,
    }
}

fn bitwise_flags_predicate(left: &Expr, right: &Expr) -> Option<(String, i64, i64)> {
    let Expr::Nested(inner) = left else {
        return None;
    };
    let Expr::BinaryOp {
        left: column,
        op: BinaryOperator::BitwiseAnd,
        right: mask,
    } = inner.as_ref()
    else {
        return None;
    };
    let (alias, column) = column_expr(column)?;
    if column != "access_flags" {
        return None;
    }
    let Expr::Value(mask) = mask.as_ref() else {
        return None;
    };
    let Scalar::Int(mask) = scalar_value(mask)? else {
        return None;
    };
    let Expr::Value(expected) = right else {
        return None;
    };
    let Scalar::Int(expected) = scalar_value(expected)? else {
        return None;
    };
    Some((alias?, mask, expected))
}

fn param_descriptors(file: &DexFile, proto: &dexsql_cache::ProtoInfo) -> String {
    let mut descriptor = String::new();
    for (index, param) in proto.parameters.iter().enumerate() {
        if index > 0 {
            descriptor.push(',');
        }
        descriptor.push_str(file.type_descriptor(*param as u32));
    }
    descriptor
}

fn method_matches(file: &DexFile, method_idx: u32, filter: &MethodFilter) -> bool {
    if filter.is_empty() {
        return true;
    }
    let Some(method) = file.methods.get(method_idx as usize) else {
        return false;
    };
    let class = file.type_descriptor(method.class_idx as u32);
    if !filter.classes.is_empty() && !filter.classes.iter().any(|value| value == class) {
        return false;
    }
    if !filter.class_likes.is_empty()
        && !filter
            .class_likes
            .iter()
            .any(|need| plain_like_match(class, need))
    {
        return false;
    }
    if !filter.excluded_class_likes.is_empty()
        && filter
            .excluded_class_likes
            .iter()
            .any(|need| plain_like_match(class, need))
    {
        return false;
    }
    let name = file.string(method.name_idx);
    if !filter.names.is_empty() && !filter.names.iter().any(|value| value == name) {
        return false;
    }
    let Some(proto) = file.protos.get(method.proto_idx as usize) else {
        return false;
    };
    if !filter.returns.is_empty() {
        let returns = file.type_descriptor(proto.return_type_idx);
        if !filter
            .returns
            .iter()
            .any(|need| plain_like_match(returns, need))
        {
            return false;
        }
    }
    let param_count = proto.parameters.len() as i64;
    if !filter.param_counts.is_empty() && !filter.param_counts.contains(&param_count) {
        return false;
    }
    if filter
        .param_count_min
        .iter()
        .any(|minimum| param_count < *minimum)
    {
        return false;
    }
    if filter
        .param_count_max
        .iter()
        .any(|maximum| param_count > *maximum)
    {
        return false;
    }
    if !filter.param_patterns.is_empty()
        && !filter.param_patterns.iter().all(|pattern| {
            pattern.matches_params(proto.parameters.len(), |index| {
                file.type_descriptor(proto.parameters[index] as u32)
            })
        })
    {
        return false;
    }
    if !filter.param_pattern_any.is_empty()
        && !filter.param_pattern_any.iter().any(|pattern| {
            pattern.matches_params(proto.parameters.len(), |index| {
                file.type_descriptor(proto.parameters[index] as u32)
            })
        })
    {
        return false;
    }
    if !filter.param_descriptors.is_empty() {
        let descriptor = param_descriptors(file, proto);
        if !filter
            .param_descriptors
            .iter()
            .any(|value| value == &descriptor)
        {
            return false;
        }
    }
    if !filter.flags.is_empty() {
        let Some(flags) = file.method_access_flags(method_idx) else {
            return false;
        };
        let flags = flags as i64;
        if !filter
            .flags
            .iter()
            .all(|(mask, expected)| flags & mask == *expected)
        {
            return false;
        }
    }
    if filter.opcode_count_min.is_some() || filter.opcode_count_max.is_some() {
        let Some(count) = file.method_opcode_count(method_idx) else {
            return false;
        };
        let count = count as i64;
        if filter
            .opcode_count_min
            .is_some_and(|minimum| count < minimum)
            || filter
                .opcode_count_max
                .is_some_and(|maximum| count > maximum)
        {
            return false;
        }
    }
    true
}

fn string_candidate_methods(file: &DexFile, need: &StringNeed) -> HashSet<u32> {
    let mut out = HashSet::new();
    if need.mode == LikeMode::Equal && !need.case_insensitive {
        if let Some(string_idx) = file.find_string_idx(&need.value) {
            if let Some(methods) = file.method_strings_by_string.get(&string_idx) {
                out.extend(methods.iter().copied());
            }
        }
        return out;
    }
    for (string_idx, value) in file.strings.iter().enumerate() {
        if !plain_like_match(value, need) {
            continue;
        }
        if let Some(methods) = file.method_strings_by_string.get(&(string_idx as u32)) {
            out.extend(methods.iter().copied());
        }
    }
    out
}

fn candidate_methods(file: &DexFile, filter: &MethodFilter) -> Option<HashSet<u32>> {
    let mut candidate: Option<HashSet<u32>> = None;
    for need in &filter.strings {
        let strings = string_candidate_methods(file, need);
        candidate = Some(match candidate {
            None => strings,
            Some(previous) => previous
                .into_iter()
                .filter(|method| strings.contains(method))
                .collect(),
        });
        if candidate.as_ref().is_some_and(HashSet::is_empty) {
            return candidate;
        }
    }
    for number in &filter.numbers {
        let numbers: HashSet<u32> = file
            .method_numbers_by_value
            .get(number)
            .map(|methods| methods.iter().copied().collect())
            .unwrap_or_default();
        candidate = Some(match candidate {
            None => numbers,
            Some(previous) => previous
                .into_iter()
                .filter(|method| numbers.contains(method))
                .collect(),
        });
        if candidate.as_ref().is_some_and(HashSet::is_empty) {
            return candidate;
        }
    }
    for expected in &filter.doubles {
        // The cache has no f64 inverted index; this scan is bounded by the
        // method-number relation (one row per numeric constant reference) and
        // still replaces the generic executor's full row materialization.
        let numbers: HashSet<u32> = file
            .method_numbers
            .iter()
            .filter(|row| row.double_value.is_some_and(|value| value == *expected))
            .map(|row| row.method_idx)
            .collect();
        candidate = Some(match candidate {
            None => numbers,
            Some(previous) => previous
                .into_iter()
                .filter(|method| numbers.contains(method))
                .collect(),
        });
        if candidate.as_ref().is_some_and(HashSet::is_empty) {
            return candidate;
        }
    }
    candidate
}

fn filtered_methods(file: &DexFile, filter: &MethodFilter) -> Vec<u32> {
    match candidate_methods(file, filter) {
        Some(candidates) => candidates
            .into_iter()
            .filter(|method| method_matches(file, *method, filter))
            .collect(),
        None => (0..file.methods.len() as u32)
            .filter(|method| method_matches(file, *method, filter))
            .collect(),
    }
}

fn projected_column(
    select: &Select,
    base_alias: &str,
) -> Option<((Option<String>, String), String)> {
    let SelectItem::ExprWithAlias { expr, alias } = &select.projection[0] else {
        return None;
    };
    let column = column_expr(expr)?;
    let label = alias.value.clone();
    if let Some(alias) = &column.0 {
        if alias != base_alias {
            return None;
        }
    }
    Some((column, label))
}

fn order_column_is(query: &sqlparser::ast::Query, column: &(Option<String>, String)) -> bool {
    let Some(order_by) = &query.order_by else {
        return false;
    };
    let sqlparser::ast::OrderByKind::Expressions(exprs) = &order_by.kind else {
        return false;
    };
    if exprs.len() != 1 || exprs[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc) {
        return false;
    }
    let Some(expr_column) = column_expr(&exprs[0].expr) else {
        return false;
    };
    expr_column.1 == column.1
}

fn apply_limit(
    mut rows: Vec<String>,
    label: String,
    limit: (Option<usize>, usize),
    cli_limit: Option<u64>,
) -> QueryResult {
    rows.sort_unstable();
    rows.dedup();
    let (sql_limit, offset) = limit;
    if offset > 0 {
        rows = rows.into_iter().skip(offset).collect();
    }
    if let Some(limit) = sql_limit {
        rows.truncate(limit);
    }
    if let Some(limit) = cli_limit {
        rows.truncate(limit as usize);
    }
    QueryResult {
        columns: vec![label],
        rows: rows.into_iter().map(|value| vec![value]).collect(),
    }
}

fn query_limit(query: &sqlparser::ast::Query) -> Option<(Option<usize>, usize)> {
    use sqlparser::ast::{Expr as AstExpr, LimitClause};
    let Some(limit_clause) = &query.limit_clause else {
        return Some((None, 0));
    };
    let (limit_expr, offset_expr): (Option<&AstExpr>, Option<&AstExpr>) = match limit_clause {
        LimitClause::LimitOffset { limit, offset, .. } => {
            (limit.as_ref(), offset.as_ref().map(|value| &value.value))
        }
        LimitClause::OffsetCommaLimit { limit, offset } => (Some(limit), Some(offset)),
    };
    let parse = |expr: &AstExpr| -> Option<usize> {
        match expr {
            AstExpr::Value(value) => match &value.value {
                Value::Number(text, _) => text.parse().ok(),
                _ => None,
            },
            _ => None,
        }
    };
    let limit = match limit_expr {
        Some(expr) => Some(parse(expr)?),
        None => None,
    };
    let offset = match offset_expr {
        Some(offset) => parse(offset)?,
        None => 0,
    };
    Some((limit, offset))
}

fn add_predicate(filter: &mut MethodFilter, table: &str, pred: &Pred) -> Option<()> {
    match table {
        "method_strings" => {
            if pred.column != "value" {
                return None;
            }
            match pred.kind {
                PredKind::NotContains | PredKind::NotPrefix => return None,
                PredKind::Eq => filter.strings.push(StringNeed {
                    mode: LikeMode::Equal,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Like => filter
                    .strings
                    .push(parse_like_pattern(pred.text()?, pred.escape)?),
                PredKind::Contains => filter.strings.push(StringNeed {
                    mode: LikeMode::Contains,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Prefix => filter.strings.push(StringNeed {
                    mode: LikeMode::Prefix,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Suffix => filter.strings.push(StringNeed {
                    mode: LikeMode::Suffix,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Flags(_)
                | PredKind::ParamTypesMatch
                | PredKind::ParamTypesMatchAny
                | PredKind::Gte
                | PredKind::Lte => return None,
            }
        }
        "method_using_numbers" => match pred.column.as_str() {
            "long_value" if matches!(pred.kind, PredKind::Eq) => {
                filter.numbers.push(pred.int()?);
            }
            "double_value" if matches!(pred.kind, PredKind::Eq) => {
                filter.doubles.push(pred.double()?);
            }
            _ => return None,
        },
        "methods" => match pred.column.as_str() {
            "access_flags" => match pred.kind {
                PredKind::Flags(mask) => filter.flags.push((mask, pred.int()?)),
                _ => return None,
            },
            "name" if matches!(pred.kind, PredKind::Eq) => {
                filter.names.push(pred.text()?.to_owned())
            }
            "class_descriptor" => match pred.kind {
                PredKind::Eq => filter.classes.push(pred.text()?.to_owned()),
                PredKind::NotPrefix => filter.excluded_class_likes.push(StringNeed {
                    mode: LikeMode::Prefix,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::NotContains => filter.excluded_class_likes.push(StringNeed {
                    mode: LikeMode::Contains,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Flags(_) => return None,
                _ => filter.class_likes.push(class_descriptor_need(pred)?),
            },
            "return_descriptor" => match pred.kind {
                PredKind::NotContains | PredKind::NotPrefix => return None,
                PredKind::Eq => filter.returns.push(StringNeed {
                    mode: LikeMode::Equal,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Like => filter
                    .returns
                    .push(parse_like_pattern(pred.text()?, pred.escape)?),
                PredKind::Contains => filter.returns.push(StringNeed {
                    mode: LikeMode::Contains,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Prefix => filter.returns.push(StringNeed {
                    mode: LikeMode::Prefix,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Suffix => filter.returns.push(StringNeed {
                    mode: LikeMode::Suffix,
                    value: pred.text()?.to_owned(),
                    case_insensitive: false,
                }),
                PredKind::Flags(_)
                | PredKind::ParamTypesMatch
                | PredKind::ParamTypesMatchAny
                | PredKind::Gte
                | PredKind::Lte => return None,
            },
            "param_count" => match pred.kind {
                PredKind::Eq => filter.param_counts.push(pred.int()?),
                PredKind::Gte => filter.param_count_min.push(pred.int()?),
                PredKind::Lte => filter.param_count_max.push(pred.int()?),
                _ => return None,
            },
            "param_descriptors" => match pred.kind {
                PredKind::Eq => filter.param_descriptors.push(pred.text()?.to_owned()),
                PredKind::ParamTypesMatch => filter
                    .param_patterns
                    .push(ParamPattern::parse(pred.text()?)),
                PredKind::ParamTypesMatchAny => filter
                    .param_pattern_any
                    .push(ParamPattern::parse(pred.text()?)),
                _ => return None,
            },
            "opcode_count" => {
                let value = pred.int()?;
                match pred.kind {
                    PredKind::Eq => {
                        filter.opcode_count_min = Some(value);
                        filter.opcode_count_max = Some(value);
                    }
                    PredKind::Gte => filter.opcode_count_min = Some(value),
                    PredKind::Lte => filter.opcode_count_max = Some(value),
                    _ => return None,
                }
            }
            _ => return None,
        },
        _ => return None,
    }
    Some(())
}

fn method_filter_for_alias(
    alias: &str,
    factors: &[Factor],
    predicates: &[Pred],
) -> Option<MethodFilter> {
    let mut filter = MethodFilter::default();
    for pred in predicates {
        if pred.alias.as_deref() != Some(alias) {
            continue;
        }
        let table = table_for(factors, alias)?;
        add_predicate(&mut filter, table, pred)?;
    }
    Some(filter)
}

fn access_filter_for_alias(
    alias: &str,
    factors: &[Factor],
    predicates: &[Pred],
) -> Result<RelationAccessFilter, String> {
    let mut filter = RelationAccessFilter::default();
    for pred in predicates {
        if pred.alias.as_deref() != Some(alias) {
            continue;
        }
        match pred.column.as_str() {
            "field" if matches!(pred.kind, PredKind::Eq) => {
                filter
                    .fields
                    .push(pred.text().ok_or("bad field access descriptor")?.to_owned());
            }
            "using_type" if matches!(pred.kind, PredKind::Eq) => {
                filter
                    .using_types
                    .push(pred.text().ok_or("bad field access using type")?.to_owned());
            }
            "field_name" if matches!(pred.kind, PredKind::Eq) => {
                filter
                    .field_names
                    .push(pred.text().ok_or("bad field access name")?.to_owned());
            }
            "field_type" if matches!(pred.kind, PredKind::Eq) => {
                filter
                    .field_types
                    .push(pred.text().ok_or("bad field access type")?.to_owned());
            }
            "file_id" | "method_idx" => {}
            _ => return Err("unsupported fast field access predicate".into()),
        }
    }
    let _ = factors;
    Ok(filter)
}

fn access_using_type(opcode: u8) -> &'static str {
    // DEX field opcodes: iget/iget-wide/iget-object/iget-boolean/iget-byte/
    // iget-char/iget-short are reads; iput* are writes. This mirrors the
    // generic executor/run_field_lookup classification.
    if matches!(opcode, 0x52..=0x58 | 0x60..=0x66) {
        "get"
    } else {
        "put"
    }
}

fn field_access_methods(file: &DexFile, filter: &RelationAccessFilter) -> HashSet<u32> {
    file.method_field_accesses
        .iter()
        .filter(|access| {
            if !filter.fields.is_empty()
                && !filter
                    .fields
                    .iter()
                    .any(|value| value.as_str() == file.field_descriptor_ref(access.field_idx))
            {
                return false;
            }
            if !filter.using_types.is_empty()
                && !filter
                    .using_types
                    .iter()
                    .any(|value| value.as_str() == access_using_type(access.opcode))
            {
                return false;
            }
            if !filter.field_names.is_empty() || !filter.field_types.is_empty() {
                let Some((name, field_type)) =
                    field_descriptor_parts(file.field_descriptor_ref(access.field_idx))
                else {
                    return false;
                };
                if !filter.field_names.is_empty()
                    && !filter
                        .field_names
                        .iter()
                        .any(|value| value.as_str() == name)
                {
                    return false;
                }
                if !filter.field_types.is_empty()
                    && !filter
                        .field_types
                        .iter()
                        .any(|value| value.as_str() == field_type)
                {
                    return false;
                }
            }
            true
        })
        .map(|access| access.method_idx)
        .collect()
}

fn other_join_alias(columns: &JoinColumns, alias: &str) -> Option<String> {
    for (candidate, _) in [&columns.0, &columns.1] {
        if let Some(candidate) = candidate {
            if candidate != alias {
                return Some(candidate.clone());
            }
        }
    }
    None
}

fn is_superclass_unit_join(columns: &JoinColumns, methods_alias: &str) -> bool {
    let methods_side = |alias: &Option<String>, column: &str| {
        alias.as_deref() == Some(methods_alias) && column == "class_descriptor"
    };
    let other_side = |column: &str| column == "superclass_descriptor";
    (methods_side(&columns.0 .0, &columns.0 .1) && other_side(&columns.1 .1))
        || (methods_side(&columns.1 .0, &columns.1 .1) && other_side(&columns.0 .1))
}

fn is_annotation_owner_join(columns: &JoinColumns, base_alias: &str) -> Option<String> {
    // annotation_elements_resolved.owner = <base>.class_descriptor
    let base_side = |alias: &Option<String>, column: &str| {
        column == "class_descriptor" && alias.as_deref() == Some(base_alias)
    };
    let owner_side = |alias: &Option<String>, column: &str| column == "owner" && alias.is_some();
    if owner_side(&columns.0 .0, &columns.0 .1) && base_side(&columns.1 .0, &columns.1 .1) {
        return columns.0 .0.clone();
    }
    if owner_side(&columns.1 .0, &columns.1 .1) && base_side(&columns.0 .0, &columns.0 .1) {
        return columns.1 .0.clone();
    }
    None
}

fn is_same_column_join(
    columns: &JoinColumns,
    column: &str,
    known: &[String],
) -> Option<(String, String)> {
    let (left_alias, left_column) = (&columns.0 .0, &columns.0 .1);
    let (right_alias, right_column) = (&columns.1 .0, &columns.1 .1);
    if left_column != column || right_column != column {
        return None;
    }
    let left = left_alias.clone()?;
    let right = right_alias.clone()?;
    if known.contains(&right) && !known.contains(&left) {
        return Some((left, right));
    }
    if known.contains(&left) && !known.contains(&right) {
        return Some((right, left));
    }
    None
}

fn is_string_index_join(columns: &JoinColumns, known: &[String]) -> Option<(String, String)> {
    let left = (columns.0 .0.clone()?, columns.0 .1.as_str());
    let right = (columns.1 .0.clone()?, columns.1 .1.as_str());
    let matches = |string_column: &str, index_column: &str| {
        (string_column == "string_idx" && index_column == "value_index")
            || (string_column == "value_index" && index_column == "string_idx")
    };
    if matches(left.1, right.1) {
        if known.contains(&right.0) && !known.contains(&left.0) {
            return Some((left.0, right.0));
        }
        if known.contains(&left.0) && !known.contains(&right.0) {
            return Some((right.0, left.0));
        }
    }
    None
}

/// One class-annotation constraint of a method lookup: annotation type, visibility and (for an
/// array-valued template) the ordered expected string values.
#[derive(Debug, Clone, Default)]
struct AnnotationUnit {
    annotation: Option<String>,
    visibility: Option<i64>,
    element_name: Option<String>,
    /// Expected ordered array strings; empty means the annotation only has to be present.
    values: Vec<Option<String>>,
}

fn annotation_unit_matches(annotations: &[serde_json::Value], unit: &AnnotationUnit) -> bool {
    annotations.iter().any(|annotation| {
        let Some(object) = annotation.as_object() else {
            return false;
        };
        if let Some(expected) = &unit.annotation {
            if object.get("type").and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
                return false;
            }
        }
        if let Some(visibility) = unit.visibility {
            let expected = match visibility {
                0 => "build",
                1 => "runtime",
                2 => "system",
                _ => return false,
            };
            if object.get("visibility").and_then(serde_json::Value::as_str) != Some(expected) {
                return false;
            }
        }
        let Some(element_name) = &unit.element_name else {
            return true;
        };
        let Some(elements) = object.get("elements").and_then(serde_json::Value::as_array) else {
            return false;
        };
        let Some(element) = elements.iter().find(|element| {
            element
                .as_object()
                .and_then(|element| element.get("name"))
                .and_then(serde_json::Value::as_str)
                == Some(element_name.as_str())
        }) else {
            return false;
        };
        let expected_values: Vec<&str> = unit
            .values
            .iter()
            .map(|value| value.as_deref().unwrap_or_default())
            .collect();
        let Some(actual) = element
            .as_object()
            .and_then(|element| element.get("value"))
            .and_then(serde_json::Value::as_array)
        else {
            return false;
        };
        actual.len() == expected_values.len()
            && actual
                .iter()
                .zip(expected_values.iter())
                .all(|(actual, expected)| actual.as_str() == Some(*expected))
    })
}

fn method_matches_annotation_units(
    file: &DexFile,
    method_idx: u32,
    units: &[AnnotationUnit],
) -> bool {
    let Some(method) = file.methods.get(method_idx as usize) else {
        return false;
    };
    let Some(class) = file.class_for_type_idx(method.class_idx as u32) else {
        return false;
    };
    let Ok(annotations) = dexsql_cache::annotations::class_annotations(file, class) else {
        return false;
    };
    let Some(annotations) = annotations.as_array() else {
        return false;
    };
    units
        .iter()
        .all(|unit| annotation_unit_matches(annotations, unit))
}

fn collect_annotation_units(
    annotation_aliases: &[String],
    annotation_element_aliases: &[(String, String)],
    annotation_string_aliases: &[(String, String, String)],
    predicates: &[Pred],
) -> Result<Vec<AnnotationUnit>, String> {
    let mut units = vec![AnnotationUnit::default(); annotation_aliases.len()];
    let mut element_ordinals: Vec<i64> = vec![-1; annotation_element_aliases.len()];
    for pred in predicates {
        let Some(alias) = pred.alias.as_deref() else {
            continue;
        };
        if let Some(index) = annotation_aliases.iter().position(|value| value == alias) {
            match pred.column.as_str() {
                "owner_kind" => {
                    if !matches!(pred.kind, PredKind::Eq) || pred.text() != Some("class") {
                        return Err("unsupported annotation owner kind".into());
                    }
                }
                "annotation" if matches!(pred.kind, PredKind::Eq) => {
                    units[index].annotation =
                        Some(pred.text().ok_or("bad annotation type")?.to_owned());
                }
                "visibility" if matches!(pred.kind, PredKind::Eq) => {
                    units[index].visibility = Some(pred.int().ok_or("bad annotation visibility")?);
                }
                "element_name" if matches!(pred.kind, PredKind::Eq) => {
                    units[index].element_name =
                        Some(pred.text().ok_or("bad annotation element name")?.to_owned());
                }
                "value_kind" => {
                    let value = pred.text().ok_or("bad annotation value kind")?;
                    if value != "array" {
                        return Err("unsupported annotation element value kind".into());
                    }
                }
                "file_id" => {}
                _ => return Err("unsupported annotation predicate".into()),
            }
            continue;
        }
        if let Some(index) = annotation_element_aliases
            .iter()
            .position(|(element, _)| element == alias)
        {
            match pred.column.as_str() {
                "depth" => {
                    if !matches!(pred.kind, PredKind::Eq) || pred.int() != Some(1) {
                        return Err("unsupported annotation element depth".into());
                    }
                }
                "ordinal" if matches!(pred.kind, PredKind::Eq) => {
                    element_ordinals[index] = pred.int().ok_or("bad annotation ordinal")?;
                }
                "value_kind" => {
                    if pred.text() != Some("string") {
                        return Err("unsupported annotation element value kind".into());
                    }
                }
                "file_id" => {}
                _ => return Err("unsupported annotation element predicate".into()),
            }
            continue;
        }
        if let Some(index) = annotation_string_aliases
            .iter()
            .position(|(string, _, _)| string == alias)
        {
            if pred.column != "value" || !matches!(pred.kind, PredKind::Eq) {
                return Err("unsupported annotation string predicate".into());
            }
            let (_, element, owner) = &annotation_string_aliases[index];
            let element_index = annotation_element_aliases
                .iter()
                .position(|(alias, _)| alias == element)
                .ok_or("annotation string without element")?;
            let owner_index = annotation_aliases
                .iter()
                .position(|value| value == owner)
                .ok_or("annotation element without owner")?;
            let ordinal = element_ordinals[element_index];
            if ordinal < 0 {
                return Err("annotation string without ordinal".into());
            }
            let value = pred.text().ok_or("bad annotation string value")?;
            let unit = &mut units[owner_index];
            if unit.values.len() <= ordinal as usize {
                unit.values.resize(ordinal as usize + 1, None);
            }
            unit.values[ordinal as usize] = Some(value.to_owned());
        }
    }
    for unit in &units {
        if unit.element_name.is_some()
            && (unit.values.is_empty() || unit.values.iter().any(Option::is_none))
        {
            return Err("incomplete annotation array constraint".into());
        }
    }
    Ok(units)
}

fn run_method_lookup(
    ds: &Dataset,
    base_alias: &str,
    factors: &[Factor],
    joins: &[JoinColumns],
    predicates: &[Pred],
    constructor: bool,
    label: String,
    limit: (Option<usize>, usize),
    cli_limit: Option<u64>,
) -> Result<QueryResult, String> {
    // Joins are either literal relations (method_strings / method_using_numbers)
    // joined to a methods alias, or class-level literal units: an extra methods
    // alias joined to the base method's class_descriptor (Pass A2
    // declaredClass { ... } constraints).
    let mut literal_aliases: Vec<(String, String)> = Vec::new();
    let mut class_unit_aliases: Vec<String> = Vec::new();
    let mut access_aliases: Vec<String> = Vec::new();
    let mut annotation_aliases: Vec<String> = Vec::new();
    let mut annotation_element_aliases: Vec<(String, String)> = Vec::new();
    let mut annotation_string_aliases: Vec<(String, String, String)> = Vec::new();
    let mut annotation_dex_aliases: Vec<(String, String)> = Vec::new();
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        match factor.table.as_str() {
            "method_strings" | "method_using_numbers" => {
                if !is_method_string_join(columns) {
                    return Err("unsupported fast lookup join".into());
                }
                let owner = literal_owner_alias(factors, joins, &factor.alias)
                    .ok_or("unsupported fast lookup literal join")?;
                literal_aliases.push((factor.alias.clone(), owner));
            }
            "methods" => {
                if !is_class_unit_join(columns) {
                    return Err("unsupported fast lookup join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported fast lookup class unit join")?;
                if other != base_alias {
                    return Err("unsupported nested class unit join".into());
                }
                class_unit_aliases.push(factor.alias.clone());
            }
            "method_field_accesses" => {
                if !is_method_access_join(columns) {
                    return Err("unsupported fast lookup field access join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported fast lookup field access join")?;
                if other != base_alias {
                    return Err("unsupported nested field access join".into());
                }
                access_aliases.push(factor.alias.clone());
            }
            "annotation_elements_resolved" => {
                if is_annotation_owner_join(columns, base_alias).as_deref()
                    != Some(factor.alias.as_str())
                {
                    return Err("unsupported annotation owner join".into());
                }
                annotation_aliases.push(factor.alias.clone());
            }
            "annotation_elements" => {
                let Some((alias, owner)) =
                    is_same_column_join(columns, "annotation_off", &annotation_aliases)
                else {
                    return Err("unsupported annotation element join".into());
                };
                if alias != factor.alias {
                    return Err("unsupported annotation element alias".into());
                }
                annotation_element_aliases.push((alias, owner));
            }
            "dex_files" => {
                let known: Vec<String> = annotation_element_aliases
                    .iter()
                    .map(|(alias, _)| alias.clone())
                    .collect();
                let Some((alias, owner)) = is_same_column_join(columns, "file_id", &known) else {
                    return Err("unsupported annotation dex file join".into());
                };
                if alias != factor.alias {
                    return Err("unsupported annotation dex file alias".into());
                }
                annotation_dex_aliases.push((alias, owner));
            }
            "strings" => {
                let known: Vec<String> = annotation_element_aliases
                    .iter()
                    .map(|(alias, _)| alias.clone())
                    .collect();
                let Some((alias, owner)) = is_string_index_join(columns, &known) else {
                    return Err("unsupported annotation string join".into());
                };
                if alias != factor.alias {
                    return Err("unsupported annotation string alias".into());
                }
                let owner_of_owner = annotation_element_aliases
                    .iter()
                    .find(|(element, _)| element == &owner)
                    .map(|(_, annotation)| annotation.clone())
                    .ok_or("annotation string without element")?;
                annotation_string_aliases.push((alias, owner, owner_of_owner));
            }
            _ => return Err("unsupported fast lookup join".into()),
        }
    }
    let mut filter = method_filter_for_alias(base_alias, factors, predicates)
        .ok_or("unsupported fast lookup predicate")?;
    let mut unit_filters: Vec<MethodFilter> = class_unit_aliases
        .iter()
        .map(|alias| {
            method_filter_for_alias(alias, factors, predicates)
                .ok_or("unsupported fast class unit predicate")
        })
        .collect::<Result<_, _>>()?;
    let access_filters: Vec<RelationAccessFilter> = access_aliases
        .iter()
        .map(|alias| access_filter_for_alias(alias, factors, predicates))
        .collect::<Result<_, _>>()?;
    for (literal, owner) in &literal_aliases {
        let part = method_filter_for_alias(literal, factors, predicates)
            .ok_or("unsupported fast lookup predicate")?;
        if owner == base_alias {
            filter.merge(part);
        } else {
            let index = class_unit_aliases
                .iter()
                .position(|alias| alias == owner)
                .ok_or("unsupported fast lookup literal owner")?;
            unit_filters[index].merge(part);
        }
    }
    let annotation_units = collect_annotation_units(
        &annotation_aliases,
        &annotation_element_aliases,
        &annotation_string_aliases,
        predicates,
    )?;
    if constructor && !filter.names.iter().any(|name| name == "<init>") {
        filter.names.push("<init>".to_owned());
    }
    let files: Vec<Vec<u32>> = if !access_aliases.is_empty() {
        ds.files
            .par_iter()
            .map(|file| {
                let mut allowed: Option<HashSet<u32>> = None;
                for unit in &access_filters {
                    let methods = field_access_methods(file, unit);
                    allowed = Some(match allowed {
                        None => methods,
                        Some(previous) => previous
                            .into_iter()
                            .filter(|method| methods.contains(method))
                            .collect(),
                    });
                    if allowed.as_ref().is_some_and(HashSet::is_empty) {
                        return Vec::new();
                    }
                }
                let allowed = allowed.unwrap_or_default();
                filtered_methods(file, &filter)
                    .into_iter()
                    .filter(|method| allowed.contains(method))
                    .collect()
            })
            .collect()
    } else if class_unit_aliases.is_empty() {
        ds.files
            .par_iter()
            .map(|file| filtered_methods(file, &filter))
            .collect()
    } else {
        ds.files
            .par_iter()
            .map(|file| {
                let mut allowed: Option<HashSet<u32>> = None;
                for unit in &unit_filters {
                    let classes: HashSet<u32> = filtered_methods(file, unit)
                        .iter()
                        .filter_map(|method| {
                            file.methods
                                .get(*method as usize)
                                .map(|info| info.class_idx as u32)
                        })
                        .collect();
                    allowed = Some(match allowed {
                        None => classes,
                        Some(previous) => previous
                            .into_iter()
                            .filter(|class| classes.contains(class))
                            .collect(),
                    });
                    if allowed.as_ref().is_some_and(HashSet::is_empty) {
                        return Vec::new();
                    }
                }
                let allowed = allowed.unwrap_or_default();
                filtered_methods(file, &filter)
                    .into_iter()
                    .filter(|method| {
                        file.methods
                            .get(*method as usize)
                            .is_some_and(|info| allowed.contains(&(info.class_idx as u32)))
                    })
                    .collect()
            })
            .collect()
    };
    let files: Vec<Vec<u32>> = if annotation_units.is_empty() {
        files
    } else {
        ds.files
            .iter()
            .zip(files.iter())
            .map(|(file, methods)| {
                methods
                    .iter()
                    .copied()
                    .filter(|method| {
                        method_matches_annotation_units(file, *method, &annotation_units)
                    })
                    .collect()
            })
            .collect()
    };
    let mut rows = Vec::new();
    for (file, methods) in ds.files.iter().zip(files.iter()) {
        for method in methods {
            rows.push(file.method_descriptor_direct(*method));
        }
    }
    Ok(apply_limit(rows, label, limit, cli_limit))
}

fn literal_owner_alias(
    factors: &[Factor],
    joins: &[JoinColumns],
    literal_alias: &str,
) -> Option<String> {
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        if factor.alias != literal_alias {
            continue;
        }
        for (alias, column) in [&columns.0, &columns.1] {
            let Some(alias) = alias else { continue };
            if alias == literal_alias || column != "descriptor" {
                continue;
            }
            if table_for(factors, alias) == Some("methods") {
                return Some(alias.clone());
            }
        }
        return None;
    }
    None
}

/// Exhaustive injective assignment check used for DexKit's bipartite
/// methods-matching semantics: every nested method matcher must bind a
/// distinct method row of the class.
fn assign_distinct(unit: usize, candidates: &[Vec<u32>], used: &mut HashSet<u32>) -> bool {
    if unit == candidates.len() {
        return true;
    }
    for method in &candidates[unit] {
        if used.contains(method) {
            continue;
        }
        used.insert(*method);
        if assign_distinct(unit + 1, candidates, used) {
            return true;
        }
        used.remove(method);
    }
    false
}

fn run_class_lookup(
    ds: &Dataset,
    base_alias: &str,
    factors: &[Factor],
    joins: &[JoinColumns],
    predicates: &[Pred],
    distinct_pairs: &[(String, String)],
    label: String,
    limit: (Option<usize>, usize),
    cli_limit: Option<u64>,
) -> Result<QueryResult, String> {
    let mut unit_aliases = vec![base_alias.to_owned()];
    let mut superunit_aliases: Vec<String> = Vec::new();
    let mut class_aliases = Vec::new();
    let mut interface_aliases: Vec<String> = Vec::new();
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        match factor.table.as_str() {
            "method_strings" | "method_using_numbers" => {
                if !is_method_string_join(columns) {
                    return Err("unsupported fast class lookup join".into());
                }
            }
            "methods" => {
                if is_class_unit_join(columns) {
                    unit_aliases.push(factor.alias.clone());
                } else if is_superclass_unit_join(columns, &factor.alias) {
                    superunit_aliases.push(factor.alias.clone());
                } else {
                    return Err("unsupported fast class lookup join".into());
                }
            }
            "classes" => {
                if !is_class_join(columns) {
                    return Err("unsupported fast class lookup join".into());
                }
                class_aliases.push(factor.alias.clone());
            }
            "class_interfaces" => {
                if !is_class_interface_join(columns) {
                    return Err("unsupported fast class lookup join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported fast class interface join")?;
                if other != *base_alias && !unit_aliases.iter().any(|unit| unit == &other) {
                    return Err("unsupported fast class interface anchor".into());
                }
                interface_aliases.push(factor.alias.clone());
            }
            _ => return Err("unsupported fast class lookup join".into()),
        }
    }
    let mut units: Vec<MethodFilter> = Vec::new();
    for alias in &unit_aliases {
        units.push(
            method_filter_for_alias(alias, factors, predicates)
                .ok_or("unsupported fast class predicate")?,
        );
    }
    let mut superunits: Vec<MethodFilter> = Vec::new();
    for alias in &superunit_aliases {
        superunits.push(
            method_filter_for_alias(alias, factors, predicates)
                .ok_or("unsupported fast class superclass unit predicate")?,
        );
    }
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        if !matches!(
            factor.table.as_str(),
            "method_strings" | "method_using_numbers"
        ) {
            continue;
        }
        let owner = literal_owner_alias(factors, joins, &factor.alias)
            .or_else(|| {
                for (alias, _) in [&columns.0, &columns.1] {
                    if let Some(alias) = alias {
                        if table_for(factors, alias) == Some("methods") {
                            return Some(alias.clone());
                        }
                    }
                }
                None
            })
            .ok_or("unsupported fast class literal join")?;
        let part = method_filter_for_alias(&factor.alias, factors, predicates)
            .ok_or("unsupported fast class literal predicate")?;
        if let Some(unit_index) = unit_aliases.iter().position(|alias| alias == &owner) {
            units[unit_index].merge(part);
        } else if let Some(unit_index) = superunit_aliases.iter().position(|alias| alias == &owner)
        {
            superunits[unit_index].merge(part);
        } else {
            return Err("unsupported fast class literal owner".into());
        }
    }
    // Descriptor predicates constrain the matched class itself, not the
    // methods providing the literals.
    let mut class_constraints = MethodFilter::default();
    for pred in predicates {
        if pred.column == "class_descriptor"
            && pred
                .alias
                .as_deref()
                .is_some_and(|alias| unit_aliases.iter().any(|unit| unit == alias))
        {
            match pred.kind {
                PredKind::Eq => class_constraints
                    .classes
                    .push(pred.text().ok_or("unsupported class predicate")?.to_owned()),
                PredKind::Flags(_) => {}
                _ => class_constraints
                    .class_likes
                    .push(class_descriptor_need(pred).ok_or("unsupported class predicate")?),
            }
        }
    }
    for unit in units.iter_mut() {
        unit.classes.clear();
        unit.class_likes.clear();
    }
    let mut superclass: Vec<String> = Vec::new();
    let mut superclass_likes: Vec<StringNeed> = Vec::new();
    let mut class_flags: Vec<(i64, i64)> = Vec::new();
    let mut field_count_min: Option<i64> = None;
    let mut field_count_max: Option<i64> = None;
    let mut method_count_min: Option<i64> = None;
    let mut method_count_max: Option<i64> = None;
    let mut interface_count_min: Option<i64> = None;
    let mut interface_count_max: Option<i64> = None;
    for alias in &class_aliases {
        for pred in predicates {
            if pred.alias.as_deref() != Some(alias.as_str()) {
                continue;
            }
            match pred.column.as_str() {
                "field_count" => {
                    let value = pred.int().ok_or("bad field_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            field_count_min = Some(value);
                            field_count_max = Some(value);
                        }
                        PredKind::Gte => field_count_min = Some(value),
                        PredKind::Lte => field_count_max = Some(value),
                        _ => return Err("unsupported field_count predicate".into()),
                    }
                }
                "method_count" => {
                    let value = pred.int().ok_or("bad method_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            method_count_min = Some(value);
                            method_count_max = Some(value);
                        }
                        PredKind::Gte => method_count_min = Some(value),
                        PredKind::Lte => method_count_max = Some(value),
                        _ => return Err("unsupported method_count predicate".into()),
                    }
                }
                "interface_count" => {
                    let value = pred.int().ok_or("bad interface_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            interface_count_min = Some(value);
                            interface_count_max = Some(value);
                        }
                        PredKind::Gte => interface_count_min = Some(value),
                        PredKind::Lte => interface_count_max = Some(value),
                        _ => return Err("unsupported interface_count predicate".into()),
                    }
                }
                "superclass_descriptor" => match pred.kind {
                    PredKind::Eq => superclass.push(
                        pred.text()
                            .ok_or("unsupported superclass predicate")?
                            .to_owned(),
                    ),
                    PredKind::Flags(_)
                    | PredKind::ParamTypesMatch
                    | PredKind::Gte
                    | PredKind::Lte => return Err("unsupported superclass predicate".into()),
                    _ => superclass_likes.push(
                        class_descriptor_need(pred).ok_or("unsupported superclass predicate")?,
                    ),
                },
                "access_flags" => match pred.kind {
                    PredKind::Flags(mask) => {
                        class_flags.push((mask, pred.int().ok_or("bad class flag predicate")?))
                    }
                    _ => return Err("unsupported fast class predicate".into()),
                },
                _ => return Err("unsupported fast class predicate".into()),
            }
        }
    }
    let mut interface_units: Vec<ClassInterfaceUnit> = Vec::new();
    for alias in &interface_aliases {
        let mut unit: Option<ClassInterfaceUnit> = None;
        for pred in predicates {
            if pred.alias.as_deref() != Some(alias.as_str()) {
                continue;
            }
            match pred.column.as_str() {
                "interface_descriptor" => {
                    let need = match pred.kind {
                        PredKind::Eq => StringNeed {
                            mode: LikeMode::Equal,
                            value: pred
                                .text()
                                .ok_or("bad class interface predicate")?
                                .to_owned(),
                            case_insensitive: false,
                        },
                        PredKind::Flags(_)
                        | PredKind::ParamTypesMatch
                        | PredKind::ParamTypesMatchAny
                        | PredKind::Gte
                        | PredKind::Lte => {
                            return Err("unsupported class interface predicate".into())
                        }
                        _ => class_descriptor_need(pred)
                            .ok_or("unsupported class interface predicate")?,
                    };
                    unit = Some(ClassInterfaceUnit(need));
                }
                "file_id" | "class_idx" if matches!(pred.kind, PredKind::Eq) => {}
                _ => return Err("unsupported class interface predicate".into()),
            }
        }
        interface_units.push(unit.ok_or("class interface join without predicate")?);
    }
    if (!superclass.is_empty()
        || !superclass_likes.is_empty()
        || !class_flags.is_empty()
        || !superunits.is_empty()
        || !interface_units.is_empty()
        || method_count_min.is_some()
        || method_count_max.is_some()
        || field_count_min.is_some()
        || field_count_max.is_some()
        || interface_count_min.is_some()
        || interface_count_max.is_some())
        && ds
            .files
            .iter()
            .any(|file| file.classes.is_empty() && !file.methods.is_empty())
    {
        return Err("class definitions are not retained by this dataset".into());
    }
    // Injective nested-method matching (DexKit uses bipartite matching over
    // ClassMatcher.addMethod entries). Map each nested matcher alias to its
    // unit index; the source emits each pair at most once.
    let mut injective_units: Vec<(usize, usize)> = Vec::new();
    for (left, right) in distinct_pairs {
        let left_unit = unit_aliases.iter().position(|alias| alias == left);
        let right_unit = unit_aliases.iter().position(|alias| alias == right);
        match (left_unit, right_unit) {
            (Some(left_unit), Some(right_unit)) => injective_units.push((left_unit, right_unit)),
            (None, None)
                if interface_aliases.iter().any(|alias| alias == left)
                    && interface_aliases.iter().any(|alias| alias == right) =>
            {
                // Interface units are matched injectively by
                // class_interfaces_match, so the SQL distinctness pairs add
                // no further constraint.
            }
            _ => return Err("unsupported fast class distinctness".into()),
        }
    }
    // Superclass candidate sets are keyed by class descriptor because the
    // superclass may be defined in a different DEX than the matched class.
    let superunit_allowed: Vec<HashSet<String>> = if superunits.is_empty() {
        Vec::new()
    } else {
        let per_file: Vec<Vec<Vec<u32>>> = ds
            .files
            .par_iter()
            .map(|file| {
                superunits
                    .iter()
                    .map(|unit| {
                        filtered_methods(file, unit)
                            .iter()
                            .filter_map(|method| {
                                file.methods
                                    .get(*method as usize)
                                    .map(|info| info.class_idx as u32)
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut allowed = vec![HashSet::new(); superunits.len()];
        for (file, units) in ds.files.iter().zip(per_file.iter()) {
            for (index, classes) in units.iter().enumerate() {
                for class_idx in classes {
                    allowed[index].insert(file.type_descriptor(*class_idx).to_owned());
                }
            }
        }
        allowed
    };
    let per_file: Vec<HashSet<u32>> = ds
        .files
        .par_iter()
        .map(|file| {
            let unit_methods: Vec<Vec<u32>> = units
                .iter()
                .map(|unit| {
                    if unit.is_empty() {
                        Vec::new()
                    } else {
                        filtered_methods(file, unit)
                    }
                })
                .collect();
            let mut classes: Option<HashSet<u32>> = None;
            for (unit, methods) in units.iter().zip(unit_methods.iter()) {
                if unit.is_empty() {
                    continue;
                }
                let current: HashSet<u32> = methods
                    .iter()
                    .filter_map(|method| {
                        file.methods
                            .get(*method as usize)
                            .map(|info| info.class_idx as u32)
                    })
                    .collect();
                classes = Some(match classes {
                    None => current,
                    Some(previous) => previous
                        .into_iter()
                        .filter(|class| current.contains(class))
                        .collect(),
                });
                if classes.as_ref().is_some_and(HashSet::is_empty) {
                    return HashSet::new();
                }
            }
            // Class-projected lookups without method-unit filters must match the
            // generic methods scan, which also exposes classes that the input
            // DEX only references (they have method ids but no class definition).
            let mut classes = classes.unwrap_or_else(|| {
                file.methods_by_class
                    .keys()
                    .copied()
                    .collect::<HashSet<u32>>()
            });
            if !injective_units.is_empty() {
                // Only the nested method-matcher units listed in the pairwise
                // distinctness conditions take part in the bipartite matching;
                // class-level literal units are existential aggregate matchers
                // and may share a method with a nested unit.
                let mut injective_indices: Vec<usize> = injective_units
                    .iter()
                    .flat_map(|(left, right)| [*left, *right])
                    .collect();
                injective_indices.sort_unstable();
                injective_indices.dedup();
                classes.retain(|class_idx| {
                    let candidates: Vec<Vec<u32>> = injective_indices
                        .iter()
                        .map(|unit_index| {
                            unit_methods[*unit_index]
                                .iter()
                                .copied()
                                .filter(|method| {
                                    file.methods
                                        .get(*method as usize)
                                        .is_some_and(|info| info.class_idx as u32 == *class_idx)
                                })
                                .collect()
                        })
                        .collect();
                    let mut used = HashSet::new();
                    assign_distinct(0, &candidates, &mut used)
                });
            }
            classes
        })
        .collect();
    let mut rows = Vec::new();
    for (file, classes) in ds.files.iter().zip(per_file) {
        for class_idx in classes {
            let descriptor = file.type_descriptor(class_idx);
            if !superunit_allowed.is_empty() {
                let Some(defs) = file.classes_by_descriptor.get(&class_idx) else {
                    continue;
                };
                let satisfied = superunit_allowed.iter().all(|allowed| {
                    defs.iter().any(|def_idx| {
                        file.classes.get(*def_idx as usize).is_some_and(|class| {
                            class.superclass_idx.is_some_and(|super_idx| {
                                allowed.contains(file.type_descriptor(super_idx))
                            })
                        })
                    })
                });
                if !satisfied {
                    continue;
                }
            }
            if !class_constraints.classes.is_empty()
                && !class_constraints
                    .classes
                    .iter()
                    .any(|value| value == descriptor)
            {
                continue;
            }
            if !class_constraints.class_likes.is_empty()
                && !class_constraints
                    .class_likes
                    .iter()
                    .any(|need| plain_like_match(descriptor, need))
            {
                continue;
            }
            if !superclass.is_empty()
                || !superclass_likes.is_empty()
                || !class_flags.is_empty()
                || !interface_units.is_empty()
                || method_count_min.is_some()
                || method_count_max.is_some()
                || field_count_min.is_some()
                || field_count_max.is_some()
                || interface_count_min.is_some()
                || interface_count_max.is_some()
            {
                let Some(defs) = file.classes_by_descriptor.get(&class_idx) else {
                    continue;
                };
                let matched = defs.iter().any(|def_idx| {
                    let Some(class) = file.classes.get(*def_idx as usize) else {
                        return false;
                    };
                    let method_count = class.methods.len() as i64;
                    if method_count_min.is_some_and(|minimum| method_count < minimum)
                        || method_count_max.is_some_and(|maximum| method_count > maximum)
                    {
                        return false;
                    }
                    let field_count = class.fields.len() as i64;
                    if field_count_min.is_some_and(|minimum| field_count < minimum)
                        || field_count_max.is_some_and(|maximum| field_count > maximum)
                    {
                        return false;
                    }
                    let interface_count = class.interfaces.len() as i64;
                    if interface_count_min.is_some_and(|minimum| interface_count < minimum)
                        || interface_count_max.is_some_and(|maximum| interface_count > maximum)
                    {
                        return false;
                    }
                    if !class_interfaces_match(file, class, &interface_units) {
                        return false;
                    }
                    if !superclass.is_empty() || !superclass_likes.is_empty() {
                        let Some(super_idx) = class.superclass_idx else {
                            return false;
                        };
                        let super_descriptor = file.type_descriptor(super_idx);
                        if !superclass.is_empty()
                            && !superclass.iter().any(|value| value == super_descriptor)
                        {
                            return false;
                        }
                        if !superclass_likes.is_empty()
                            && !superclass_likes
                                .iter()
                                .any(|need| plain_like_match(super_descriptor, need))
                        {
                            return false;
                        }
                    }
                    let flags = class.access_flags as i64;
                    class_flags
                        .iter()
                        .all(|(mask, expected)| flags & mask == *expected)
                });
                if !matched {
                    continue;
                }
            }
            rows.push(descriptor.to_owned());
        }
    }
    Ok(apply_limit(rows, label, limit, cli_limit))
}

fn run_bare_class_lookup(
    ds: &Dataset,
    base_alias: &str,
    factors: &[Factor],
    joins: &[JoinColumns],
    predicates: &[Pred],
    label: String,
    limit: (Option<usize>, usize),
    cli_limit: Option<u64>,
) -> Result<QueryResult, String> {
    // Bare class queries join superclass literal units directly on the matched
    // class's superclass_descriptor (no classes intermediate alias), and declared
    // field units directly on the matched class's class_fields rows.
    let mut superunit_aliases: Vec<String> = Vec::new();
    let mut literal_aliases: Vec<(String, String)> = Vec::new();
    let mut class_field_aliases: Vec<String> = Vec::new();
    let mut interface_aliases: Vec<String> = Vec::new();
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        match factor.table.as_str() {
            "method_strings" | "method_using_numbers" => {
                if !is_method_string_join(columns) {
                    return Err("unsupported bare class join".into());
                }
                let owner = literal_owner_alias(factors, joins, &factor.alias)
                    .ok_or("unsupported bare class literal join")?;
                literal_aliases.push((factor.alias.clone(), owner));
            }
            "methods" => {
                if !is_superclass_unit_join(columns, &factor.alias) {
                    return Err("unsupported bare class join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported bare class superclass join")?;
                if other != base_alias {
                    return Err("unsupported bare class superclass anchor".into());
                }
                superunit_aliases.push(factor.alias.clone());
            }
            "class_fields" => {
                if !is_class_field_join(columns) {
                    return Err("unsupported bare class join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported bare class field join")?;
                if other != base_alias {
                    return Err("unsupported bare class field anchor".into());
                }
                class_field_aliases.push(factor.alias.clone());
            }
            "class_interfaces" => {
                if !is_class_interface_join(columns) {
                    return Err("unsupported bare class join".into());
                }
                let other = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported bare class interface join")?;
                if other != base_alias {
                    return Err("unsupported bare class interface anchor".into());
                }
                interface_aliases.push(factor.alias.clone());
            }
            _ => return Err("unsupported bare class join".into()),
        }
    }
    let mut classes = Vec::new();
    let mut class_likes: Vec<StringNeed> = Vec::new();
    let mut superclasses = Vec::new();
    let mut superclass_likes: Vec<StringNeed> = Vec::new();
    let mut class_flags: Vec<(i64, i64)> = Vec::new();
    let mut field_count_min: Option<i64> = None;
    let mut field_count_max: Option<i64> = None;
    let mut method_count_min: Option<i64> = None;
    let mut method_count_max: Option<i64> = None;
    let mut interface_count_min: Option<i64> = None;
    let mut interface_count_max: Option<i64> = None;
    let mut class_field_units: Vec<ClassFieldUnit> =
        vec![ClassFieldUnit::default(); class_field_aliases.len()];
    let mut interface_units: Vec<Option<ClassInterfaceUnit>> = vec![None; interface_aliases.len()];
    for pred in predicates {
        let Some(alias) = pred.alias.as_deref() else {
            return Err("unsupported bare class predicate".into());
        };
        if alias == base_alias {
            match pred.column.as_str() {
                "descriptor" => match pred.kind {
                    PredKind::Eq => {
                        classes.push(pred.text().ok_or("bad class predicate")?.to_owned())
                    }
                    PredKind::Flags(_) => return Err("unsupported bare class predicate".into()),
                    _ => class_likes.push(
                        class_descriptor_need(pred).ok_or("unsupported bare class predicate")?,
                    ),
                },
                "access_flags" => match pred.kind {
                    PredKind::Flags(mask) => {
                        class_flags.push((mask, pred.int().ok_or("bad class flag predicate")?))
                    }
                    _ => return Err("unsupported bare class predicate".into()),
                },
                "superclass_descriptor" => match pred.kind {
                    PredKind::Eq => {
                        superclasses.push(pred.text().ok_or("bad class predicate")?.to_owned())
                    }
                    PredKind::Flags(_)
                    | PredKind::ParamTypesMatch
                    | PredKind::Gte
                    | PredKind::Lte => return Err("unsupported superclass predicate".into()),
                    _ => superclass_likes.push(
                        class_descriptor_need(pred).ok_or("unsupported superclass predicate")?,
                    ),
                },
                "field_count" => {
                    let value = pred.int().ok_or("bad field_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            field_count_min = Some(value);
                            field_count_max = Some(value);
                        }
                        PredKind::Gte => field_count_min = Some(value),
                        PredKind::Lte => field_count_max = Some(value),
                        _ => return Err("unsupported field_count predicate".into()),
                    }
                }
                "method_count" => {
                    let value = pred.int().ok_or("bad method_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            method_count_min = Some(value);
                            method_count_max = Some(value);
                        }
                        PredKind::Gte => method_count_min = Some(value),
                        PredKind::Lte => method_count_max = Some(value),
                        _ => return Err("unsupported method_count predicate".into()),
                    }
                }
                "interface_count" => {
                    let value = pred.int().ok_or("bad interface_count predicate")?;
                    match pred.kind {
                        PredKind::Eq => {
                            interface_count_min = Some(value);
                            interface_count_max = Some(value);
                        }
                        PredKind::Gte => interface_count_min = Some(value),
                        PredKind::Lte => interface_count_max = Some(value),
                        _ => return Err("unsupported interface_count predicate".into()),
                    }
                }
                _ => return Err("unsupported bare class predicate".into()),
            }
            continue;
        }
        if let Some(index) = class_field_aliases.iter().position(|unit| unit == alias) {
            match pred.column.as_str() {
                "field_name" if matches!(pred.kind, PredKind::Eq) => {
                    class_field_units[index].name = Some(
                        pred.text()
                            .ok_or("bad class field name predicate")?
                            .to_owned(),
                    );
                }
                "field_descriptor" if matches!(pred.kind, PredKind::Contains) => {
                    let literal = pred.text().ok_or("bad class field type predicate")?;
                    let Some(field_type) = literal.strip_prefix(':') else {
                        return Err("unsupported class field descriptor predicate".into());
                    };
                    class_field_units[index].field_type = Some(field_type.to_owned());
                }
                "access_flags" => match pred.kind {
                    PredKind::Flags(mask) => class_field_units[index]
                        .flags
                        .push((mask, pred.int().ok_or("bad class field flag predicate")?)),
                    _ => return Err("unsupported class field predicate".into()),
                },
                "file_id" | "field_idx" => {}
                _ => return Err("unsupported class field predicate".into()),
            }
            continue;
        }
        if let Some(index) = interface_aliases.iter().position(|unit| unit == alias) {
            match pred.column.as_str() {
                "interface_descriptor" => {
                    let need = match pred.kind {
                        PredKind::Eq => StringNeed {
                            mode: LikeMode::Equal,
                            value: pred
                                .text()
                                .ok_or("bad class interface predicate")?
                                .to_owned(),
                            case_insensitive: false,
                        },
                        PredKind::Flags(_)
                        | PredKind::ParamTypesMatch
                        | PredKind::ParamTypesMatchAny
                        | PredKind::Gte
                        | PredKind::Lte => {
                            return Err("unsupported class interface predicate".into())
                        }
                        _ => class_descriptor_need(pred)
                            .ok_or("unsupported class interface predicate")?,
                    };
                    interface_units[index] = Some(ClassInterfaceUnit(need));
                }
                "file_id" | "class_idx" if matches!(pred.kind, PredKind::Eq) => {}
                _ => return Err("unsupported class interface predicate".into()),
            }
            continue;
        }
        // Literal predicates on superclass unit aliases are merged below.
        if !superunit_aliases.iter().any(|unit| unit == alias)
            && table_for(factors, alias) != Some("method_strings")
            && table_for(factors, alias) != Some("method_using_numbers")
        {
            return Err("unsupported bare class predicate".into());
        }
    }
    if ds
        .files
        .iter()
        .any(|file| file.classes.is_empty() && !file.methods.is_empty())
    {
        return Err("class definitions are not retained by this dataset".into());
    }
    let interface_units: Vec<ClassInterfaceUnit> = interface_units
        .into_iter()
        .map(|unit| unit.ok_or("class interface join without predicate"))
        .collect::<Result<_, _>>()?;
    let mut superunits: Vec<MethodFilter> = superunit_aliases
        .iter()
        .map(|alias| {
            method_filter_for_alias(alias, factors, predicates)
                .ok_or("unsupported bare class superclass unit predicate")
        })
        .collect::<Result<_, _>>()?;
    for (literal, owner) in &literal_aliases {
        let part = method_filter_for_alias(literal, factors, predicates)
            .ok_or("unsupported bare class literal predicate")?;
        let index = superunit_aliases
            .iter()
            .position(|alias| alias == owner)
            .ok_or("unsupported bare class literal owner")?;
        superunits[index].merge(part);
    }
    let unit_allowed: Vec<HashSet<String>> = if superunits.is_empty() {
        Vec::new()
    } else {
        let per_file: Vec<Vec<Vec<u32>>> = ds
            .files
            .par_iter()
            .map(|file| {
                superunits
                    .iter()
                    .map(|unit| {
                        filtered_methods(file, unit)
                            .iter()
                            .filter_map(|method| {
                                file.methods
                                    .get(*method as usize)
                                    .map(|info| info.class_idx as u32)
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut allowed = vec![HashSet::new(); superunits.len()];
        for (file, units) in ds.files.iter().zip(per_file.iter()) {
            for (index, classes) in units.iter().enumerate() {
                for class_idx in classes {
                    allowed[index].insert(file.type_descriptor(*class_idx).to_owned());
                }
            }
        }
        allowed
    };
    let files: Vec<Vec<u32>> = ds
        .files
        .par_iter()
        .map(|file| {
            file.classes
                .iter()
                .enumerate()
                .filter(|(_, class)| {
                    let descriptor = file.type_descriptor(class.class_idx);
                    if !classes.is_empty() && !classes.iter().any(|value| value == descriptor) {
                        return false;
                    }
                    if !class_likes.is_empty()
                        && !class_likes
                            .iter()
                            .any(|need| plain_like_match(descriptor, need))
                    {
                        return false;
                    }
                    if !superclasses.is_empty() || !superclass_likes.is_empty() {
                        let Some(super_idx) = class.superclass_idx else {
                            return false;
                        };
                        let super_descriptor = file.type_descriptor(super_idx);
                        if !superclasses.is_empty()
                            && !superclasses.iter().any(|value| value == super_descriptor)
                        {
                            return false;
                        }
                        if !superclass_likes.is_empty()
                            && !superclass_likes
                                .iter()
                                .any(|need| plain_like_match(super_descriptor, need))
                        {
                            return false;
                        }
                    }
                    let flags = class.access_flags as i64;
                    if !class_flags
                        .iter()
                        .all(|(mask, expected)| flags & mask == *expected)
                    {
                        return false;
                    }
                    let field_count = class.fields.len() as i64;
                    if field_count_min.is_some_and(|minimum| field_count < minimum)
                        || field_count_max.is_some_and(|maximum| field_count > maximum)
                    {
                        return false;
                    }
                    let method_count = class.methods.len() as i64;
                    if method_count_min.is_some_and(|minimum| method_count < minimum)
                        || method_count_max.is_some_and(|maximum| method_count > maximum)
                    {
                        return false;
                    }
                    let interface_count = class.interfaces.len() as i64;
                    if interface_count_min.is_some_and(|minimum| interface_count < minimum)
                        || interface_count_max.is_some_and(|maximum| interface_count > maximum)
                    {
                        return false;
                    }
                    if !class_interfaces_match(file, class, &interface_units) {
                        return false;
                    }
                    if !class_field_units.is_empty()
                        && !class_fields_match(file, class, &class_field_units)
                    {
                        return false;
                    }
                    if !superunits.is_empty() {
                        for set in &unit_allowed {
                            let Some(super_idx) = class.superclass_idx else {
                                return false;
                            };
                            if !set.contains(file.type_descriptor(super_idx)) {
                                return false;
                            }
                        }
                    }
                    true
                })
                .map(|(index, _)| index as u32)
                .collect()
        })
        .collect();
    let mut rows = Vec::new();
    for (file, classes) in ds.files.iter().zip(files.iter()) {
        for class in classes {
            let descriptor = file.type_descriptor(file.classes[*class as usize].class_idx);
            rows.push(descriptor.to_owned());
        }
    }
    Ok(apply_limit(rows, label, limit, cli_limit))
}

#[derive(Debug, Clone, Default)]
struct FieldFilter {
    names: Vec<String>,
    classes: Vec<String>,
    class_likes: Vec<StringNeed>,
    types: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct FieldAccessUnit {
    using_types: Vec<String>,
    methods: MethodFilter,
}

/// One method-base field-access relation unit: the base method must access a
/// field matching the descriptor literal with the requested using_type.
#[derive(Debug, Clone, Default)]
struct RelationAccessFilter {
    fields: Vec<String>,
    field_names: Vec<String>,
    field_types: Vec<String>,
    using_types: Vec<String>,
}

/// One declared-field unit of a bare-class lookup: the class must declare a
/// field matching every predicate, and units are matched injectively.
#[derive(Debug, Clone, Default)]
struct ClassFieldUnit {
    name: Option<String>,
    field_type: Option<String>,
    flags: Vec<(i64, i64)>,
}

fn is_class_field_join(columns: &JoinColumns) -> bool {
    (columns.0 .1 == "class_descriptor" && columns.1 .1 == "descriptor")
        || (columns.0 .1 == "descriptor" && columns.1 .1 == "class_descriptor")
}

fn is_class_interface_join(columns: &JoinColumns) -> bool {
    columns.0 .1 == "class_idx" && columns.1 .1 == "class_idx"
}

/// One directly-declared interface unit of a class lookup: the matched class must
/// declare an interface whose descriptor matches the predicate; units are injective.
#[derive(Debug, Clone)]
struct ClassInterfaceUnit(StringNeed);

/// Injective matching of declared-interface units against one class's interface list.
fn class_interfaces_match(
    file: &DexFile,
    class: &dexsql_cache::ClassInfo,
    units: &[ClassInterfaceUnit],
) -> bool {
    fn match_unit(
        file: &DexFile,
        class: &dexsql_cache::ClassInfo,
        units: &[ClassInterfaceUnit],
        index: usize,
        used: &mut HashSet<usize>,
    ) -> bool {
        if index == units.len() {
            return true;
        }
        let unit = &units[index];
        for (position, interface) in class.interfaces.iter().enumerate() {
            if used.contains(&position) {
                continue;
            }
            if !plain_like_match(file.type_descriptor(*interface as u32), &unit.0) {
                continue;
            }
            used.insert(position);
            if match_unit(file, class, units, index + 1, used) {
                return true;
            }
            used.remove(&position);
        }
        false
    }
    let mut used = HashSet::new();
    match_unit(file, class, units, 0, &mut used)
}

/// Injective matching of declared-field units against one class's field list.
fn class_fields_match(
    file: &DexFile,
    class: &dexsql_cache::ClassInfo,
    units: &[ClassFieldUnit],
) -> bool {
    fn match_unit(
        file: &DexFile,
        class: &dexsql_cache::ClassInfo,
        units: &[ClassFieldUnit],
        index: usize,
        used: &mut HashSet<u32>,
    ) -> bool {
        if index == units.len() {
            return true;
        }
        let unit = &units[index];
        for field in &class.fields {
            if used.contains(&field.field_idx) {
                continue;
            }
            let descriptor = file.field_descriptor_ref(field.field_idx);
            let Some((name, field_type)) = field_descriptor_parts(descriptor) else {
                continue;
            };
            if unit.name.as_deref().is_some_and(|value| value != name) {
                continue;
            }
            if unit
                .field_type
                .as_deref()
                .is_some_and(|value| value != field_type)
            {
                continue;
            }
            let flags = field.access_flags as i64;
            if !unit
                .flags
                .iter()
                .all(|(mask, expected)| flags & mask == *expected)
            {
                continue;
            }
            used.insert(field.field_idx);
            if match_unit(file, class, units, index + 1, used) {
                return true;
            }
            used.remove(&field.field_idx);
        }
        false
    }
    let mut used = HashSet::new();
    match_unit(file, class, units, 0, &mut used)
}

/** Split a field descriptor ("Lpkg/Class;->name:Type;") into its name and type descriptor. */
fn field_descriptor_parts(descriptor: &str) -> Option<(&str, &str)> {
    let arrow = descriptor.find("->")?;
    let rest = &descriptor[arrow + 2..];
    let colon = rest.find(':')?;
    Some((&rest[..colon], &rest[colon + 1..]))
}

fn run_field_lookup(
    ds: &Dataset,
    base_alias: &str,
    factors: &[Factor],
    joins: &[JoinColumns],
    predicates: &[Pred],
    label: String,
    limit: (Option<usize>, usize),
    cli_limit: Option<u64>,
) -> Result<QueryResult, String> {
    // Each method_field_accesses join is an independent field-access unit: a
    // method matching that unit's method filter must access the field with the
    // requested using_type. Multiple units are all required, but they may bind
    // different methods (no injective requirement for field accessors).
    let mut access_aliases: Vec<String> = Vec::new();
    let mut method_aliases: Vec<String> = Vec::new();
    let mut method_by_access: Vec<(String, String)> = Vec::new();
    let mut literal_aliases: Vec<(String, String)> = Vec::new();
    for (index, columns) in joins.iter().enumerate() {
        let factor = &factors[index + 1];
        match factor.table.as_str() {
            "method_strings" | "method_using_numbers" => {
                if !is_method_string_join(columns) {
                    return Err("unsupported fast field join".into());
                }
                let owner = literal_owner_alias(factors, joins, &factor.alias)
                    .ok_or("unsupported fast field literal join")?;
                literal_aliases.push((factor.alias.clone(), owner));
            }
            "methods" => {
                if !is_method_access_join(columns) {
                    return Err("unsupported fast field join".into());
                }
                let access_alias = other_join_alias(columns, &factor.alias)
                    .ok_or("unsupported fast field access join")?;
                if !access_aliases.iter().any(|alias| alias == &access_alias) {
                    if table_for(factors, &access_alias) == Some("method_field_accesses") {
                        access_aliases.push(access_alias.clone());
                    } else {
                        return Err("unsupported fast field join".into());
                    }
                }
                method_aliases.push(factor.alias.clone());
                method_by_access.push((access_alias, factor.alias.clone()));
            }
            "method_field_accesses" => {
                if !is_field_access_join(columns) {
                    return Err("unsupported fast field join".into());
                }
                access_aliases.push(factor.alias.clone());
            }
            _ => return Err("unsupported fast field join".into()),
        }
    }
    for alias in &access_aliases {
        if !method_by_access.iter().any(|(access, _)| access == alias) {
            return Err("unsupported fast field access join".into());
        }
    }
    let mut filter = FieldFilter::default();
    let mut unit_using_types: Vec<Vec<String>> = vec![Vec::new(); access_aliases.len()];
    let mut unit_methods: Vec<MethodFilter> = method_aliases
        .iter()
        .map(|alias| method_filter_for_alias(alias, factors, predicates))
        .collect::<Option<Vec<_>>>()
        .ok_or("unsupported fast field method predicate")?;
    for pred in predicates {
        let Some(alias) = pred.alias.as_deref() else {
            return Err("unsupported fast field predicate".into());
        };
        if alias == base_alias {
            match pred.column.as_str() {
                "name" if matches!(pred.kind, PredKind::Eq) => filter
                    .names
                    .push(pred.text().ok_or("bad field predicate")?.to_owned()),
                "class_descriptor" => match pred.kind {
                    PredKind::Eq => filter
                        .classes
                        .push(pred.text().ok_or("bad field predicate")?.to_owned()),
                    PredKind::Flags(_) => return Err("unsupported fast field predicate".into()),
                    _ => filter
                        .class_likes
                        .push(class_descriptor_need(pred).ok_or("bad field predicate")?),
                },
                "type_descriptor" if matches!(pred.kind, PredKind::Eq) => filter
                    .types
                    .push(pred.text().ok_or("bad field predicate")?.to_owned()),
                _ => return Err("unsupported fast field predicate".into()),
            }
            continue;
        }
        let table = table_for(factors, alias).ok_or("unknown field predicate alias")?;
        match table {
            "method_field_accesses" => {
                if pred.column != "using_type" || !matches!(pred.kind, PredKind::Eq) {
                    return Err("unsupported fast field access predicate".into());
                }
                let unit = access_aliases
                    .iter()
                    .position(|candidate| candidate == alias)
                    .ok_or("unknown fast field access alias")?;
                unit_using_types[unit].push(pred.text().ok_or("bad field predicate")?.to_owned());
            }
            "methods" | "method_strings" | "method_using_numbers" => {}
            _ => return Err("unsupported fast field predicate".into()),
        }
    }
    for (literal, owner) in &literal_aliases {
        let part = method_filter_for_alias(literal, factors, predicates)
            .ok_or("unsupported fast field literal predicate")?;
        let index = method_aliases
            .iter()
            .position(|alias| alias == owner)
            .ok_or("unsupported fast field literal owner")?;
        unit_methods[index].merge(part);
    }
    let units: Vec<FieldAccessUnit> = access_aliases
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let method_alias = method_by_access
                .iter()
                .find(|(access, _)| access == &access_aliases[index])
                .map(|(_, method)| method.clone())
                .ok_or("missing fast field access method alias");
            method_alias.map(|method_alias| {
                let method_index = method_aliases
                    .iter()
                    .position(|alias| alias == &method_alias)
                    .unwrap_or(0);
                FieldAccessUnit {
                    using_types: unit_using_types[index].clone(),
                    methods: unit_methods[method_index].clone(),
                }
            })
        })
        .collect::<Result<_, _>>()?;
    let files: Vec<Vec<u32>> = ds
        .files
        .par_iter()
        .map(|file| {
            let mut fields: Option<HashSet<u32>> = None;
            for unit in &units {
                let methods: Option<HashSet<u32>> = if unit.methods.is_empty() {
                    None
                } else {
                    Some(filtered_methods(file, &unit.methods).into_iter().collect())
                };
                let unit_fields: HashSet<u32> = file
                    .method_field_accesses
                    .iter()
                    .filter(|access| {
                        if let Some(methods) = &methods {
                            if !methods.contains(&access.method_idx) {
                                return false;
                            }
                        }
                        if !unit.using_types.is_empty() {
                            let using = if (0x52..=0x58).contains(&access.opcode)
                                || (0x60..=0x66).contains(&access.opcode)
                            {
                                "get"
                            } else {
                                "put"
                            };
                            if !unit.using_types.iter().any(|value| value == using) {
                                return false;
                            }
                        }
                        true
                    })
                    .map(|access| access.field_idx)
                    .collect();
                fields = Some(match fields {
                    None => unit_fields,
                    Some(previous) => previous
                        .into_iter()
                        .filter(|field| unit_fields.contains(field))
                        .collect(),
                });
                if fields.as_ref().is_some_and(HashSet::is_empty) {
                    return Vec::new();
                }
            }
            let fields = fields.unwrap_or_else(|| (0..file.fields.len() as u32).collect());
            fields
                .into_iter()
                .filter(|field_idx| {
                    let Some(field) = file.fields.get(*field_idx as usize) else {
                        return false;
                    };
                    let class = file.type_descriptor(field.class_idx as u32);
                    if !filter.names.is_empty()
                        && !filter
                            .names
                            .iter()
                            .any(|value| value == file.string(field.name_idx))
                    {
                        return false;
                    }
                    if !filter.classes.is_empty()
                        && !filter.classes.iter().any(|value| value == class)
                    {
                        return false;
                    }
                    if !filter.class_likes.is_empty()
                        && !filter
                            .class_likes
                            .iter()
                            .any(|need| plain_like_match(class, need))
                    {
                        return false;
                    }
                    if !filter.types.is_empty() {
                        let field_type = file.type_descriptor(field.type_idx as u32);
                        if !filter.types.iter().any(|value| value == field_type) {
                            return false;
                        }
                    }
                    true
                })
                .collect()
        })
        .collect();
    let mut rows = Vec::new();
    for (file, fields) in ds.files.iter().zip(files.iter()) {
        for field in fields {
            rows.push(file.field_descriptor(*field));
        }
    }
    Ok(apply_limit(rows, label, limit, cli_limit))
}

pub(crate) fn try_fast_descriptor_lookup(
    query: &sqlparser::ast::Query,
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<QueryResult, String>> {
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select.as_ref(),
        _ => return None,
    };
    if select.distinct.is_none()
        || select.projection.len() != 1
        || select.having.is_some()
        || select.from.len() != 1
    {
        return None;
    }
    if !matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, _) if exprs.is_empty())
    {
        return None;
    }
    let (base_alias, base_table) = table_factor(&select.from[0].relation)?;
    let mut factors = vec![Factor {
        alias: base_alias.clone(),
        table: base_table.clone(),
    }];
    let mut joins = Vec::new();
    for join in &select.from[0].joins {
        let (alias, table) = table_factor(&join.relation)?;
        let columns = join_on_columns(&join.join_operator)?;
        factors.push(Factor { alias, table });
        joins.push(columns);
    }
    let (predicates, distinct_pairs) = parse_predicates(select)?;
    let target = match base_table.as_str() {
        "methods" => {
            let (column, _label) = projected_column(select, &base_alias)?;
            if column.1 == "class_descriptor" {
                Target::Class
            } else if column.1 == "descriptor" {
                let is_constructor = predicates.iter().any(|pred| {
                    pred.column == "name"
                        && matches!(pred.kind, PredKind::Eq)
                        && pred.alias.as_deref() == Some(base_alias.as_str())
                        && pred.text() == Some("<init>")
                });
                if is_constructor {
                    Target::Constructor
                } else {
                    Target::Method
                }
            } else {
                return None;
            }
        }
        "classes" => Target::BareClass,
        "fields" => Target::Field,
        _ => return None,
    };
    let (column, label) = projected_column(select, &base_alias)?;
    if !order_column_is(query, &column) {
        return None;
    }
    let limit = query_limit(query)?;
    let result = match target {
        Target::Method | Target::Constructor => run_method_lookup(
            ds,
            &base_alias,
            &factors,
            &joins,
            &predicates,
            target == Target::Constructor,
            label,
            limit,
            cli_limit,
        ),
        Target::Class => run_class_lookup(
            ds,
            &base_alias,
            &factors,
            &joins,
            &predicates,
            &distinct_pairs,
            label,
            limit,
            cli_limit,
        ),
        Target::BareClass => run_bare_class_lookup(
            ds,
            &base_alias,
            &factors,
            &joins,
            &predicates,
            label,
            limit,
            cli_limit,
        ),
        Target::Field => run_field_lookup(
            ds,
            &base_alias,
            &factors,
            &joins,
            &predicates,
            label,
            limit,
            cli_limit,
        ),
    };
    // The helpers report unsupported shapes as errors; fall back to the
    // generic executor instead of surfacing a lookup-only limitation.
    result.ok().map(Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_like_forms() {
        let contains = parse_like_pattern("%literal%", None).unwrap();
        assert_eq!(contains.mode, LikeMode::Contains);
        assert_eq!(contains.value, "literal");
        let prefix = parse_like_pattern("literal%", None).unwrap();
        assert_eq!(prefix.mode, LikeMode::Prefix);
        let suffix = parse_like_pattern("%literal", None).unwrap();
        assert_eq!(suffix.mode, LikeMode::Suffix);
        let equal = parse_like_pattern("literal", None).unwrap();
        assert_eq!(equal.mode, LikeMode::Equal);
    }

    #[test]
    fn rejects_complex_like_patterns() {
        assert!(parse_like_pattern("a%b", None).is_none());
        assert!(parse_like_pattern("a_b", None).is_none());
        assert!(parse_like_pattern("%%", None).is_none());
    }

    #[test]
    fn like_matches_plain_forms() {
        let need = parse_like_pattern("%bar%", None).unwrap();
        assert!(plain_like_match("foobarbaz", &need));
        assert!(!plain_like_match("foobaz", &need));
        let prefix = parse_like_pattern("foo%", None).unwrap();
        assert!(plain_like_match("foobar", &prefix));
        assert!(!plain_like_match("barfoo", &prefix));
    }

    fn parse(sql: &str) -> sqlparser::ast::Query {
        let dialect = sqlparser::dialect::SQLiteDialect {};
        let statements =
            sqlparser::parser::Parser::parse_sql(&dialect, sql).expect("parse test SQL");
        let sqlparser::ast::Statement::Query(query) = statements.into_iter().next().unwrap() else {
            panic!("not a query");
        };
        *query
    }

    #[test]
    fn accepts_method_opcode_count_lookup() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             WHERE m.name = 'op' AND m.opcode_count >= 0 AND m.opcode_count <= 10 \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "opcode_count method lookup must use the fast path"
        );
    }

    #[test]
    fn accepts_declared_class_annotation_units() {
        // Shape emitted by WeKit's declaredClass { annotation { ... } } matcher: class-owner
        // annotation resolution joined through annotation elements and their string array values.
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN annotation_elements_resolved ar0 ON ar0.owner = m.class_descriptor \
             JOIN annotation_elements ae0_0 ON ae0_0.annotation_off = ar0.annotation_off \
             JOIN dex_files d0_0 ON d0_0.file_id = ae0_0.file_id \
             JOIN strings s0_0 ON s0_0.string_idx = ae0_0.value_index \
             WHERE m.name = 'callback' AND m.param_count = 1 AND m.return_descriptor = 'Z' \
               AND ar0.owner_kind = 'class' \
               AND ar0.annotation = 'Ldalvik/annotation/Signature;' \
               AND ar0.visibility = 2 AND ar0.element_name = 'value' \
               AND ar0.value_kind = 'array' AND ae0_0.file_id = ar0.file_id \
               AND ae0_0.depth = 1 AND ae0_0.ordinal = 0 \
               AND ae0_0.value_kind = 'string' \
               AND s0_0.string_pool_id = d0_0.string_pool_id \
               AND s0_0.value = 'Ljava/lang/Object;' \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "declared-class annotation unit must use the fast path"
        );
    }

    #[test]
    fn accepts_or_grouped_param_types_patterns() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             WHERE m.name = 'run' \
               AND (param_types_match(m.param_descriptors, 'Ljava/lang/String;,I,I,I,Ljava/lang/Object;') = 1 \
                 OR param_types_match(m.param_descriptors, 'Ljava/lang/String;,I,I,I,Ljava/lang/Object;,Ljava/lang/String;') = 1) \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "OR-grouped param_types_match must use the fast path"
        );
    }

    #[test]
    fn accepts_or_grouped_search_packages() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN annotation_elements_resolved ar0 ON ar0.owner = m.class_descriptor \
             WHERE m.name = 'callback' \
               AND (instr(m.class_descriptor, 'Lcom/tencent/mm/voipmp/helper/') = 1 \
                 OR instr(m.class_descriptor, 'Lcom/tencent/plugin_flutter_ilinkvoip/helper/') = 1) \
               AND ar0.owner_kind = 'class' \
               AND ar0.annotation = 'Ldalvik/annotation/Signature;' \
               AND ar0.visibility = 2 \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "OR-grouped searchPackages must use the fast path"
        );
    }

    #[test]
    fn accepts_declared_class_annotation_with_exclude_packages() {
        // VoIP multitalk V2 shape: class annotation + searchPackages + excluded subpackage.
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN annotation_elements_resolved ar0 ON ar0.owner = m.class_descriptor \
             JOIN annotation_elements ae0_0 ON ae0_0.annotation_off = ar0.annotation_off \
             JOIN dex_files d0_0 ON d0_0.file_id = ae0_0.file_id \
             JOIN strings s0_0 ON s0_0.string_idx = ae0_0.value_index \
             WHERE m.name = 'callback' AND m.param_count = 1 AND m.return_descriptor = 'Z' \
               AND instr(m.class_descriptor, 'Lcom/tencent/mm/voipmp/v2/') = 1 \
               AND NOT (instr(m.class_descriptor, 'Lcom/tencent/mm/voipmp/v2/multitalk/') = 1) \
               AND ar0.owner_kind = 'class' \
               AND ar0.annotation = 'Ldalvik/annotation/Signature;' \
               AND ar0.visibility = 2 AND ar0.element_name = 'value' \
               AND ar0.value_kind = 'array' AND ae0_0.file_id = ar0.file_id \
               AND ae0_0.depth = 1 AND ae0_0.ordinal = 0 \
               AND ae0_0.value_kind = 'string' \
               AND s0_0.string_pool_id = d0_0.string_pool_id \
               AND s0_0.value = 'Ljava/lang/Object;' \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "annotation + exclude packages must use the fast path"
        );
    }

    #[test]
    fn accepts_method_access_field_type_predicate() {
        // Shape emitted by WeKit's method-level usingField { type = ... } matcher: the access unit
        // filters the accessed field type descriptor instead of the full field descriptor.
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_field_accesses uf0 ON uf0.method = m.descriptor \
             WHERE m.name = 'run' AND uf0.file_id = m.file_id \
               AND uf0.method_idx = m.method_idx AND uf0.field_type = 'I' \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "method field-access type predicate must use the fast path"
        );
    }

    #[test]
    fn accepts_bare_class_declared_field_units() {
        // Shape emitted by WeKit's class-level field { } matchers: class_fields joins with
        // name/type/flags predicates and pairwise distinctness conditions.
        let sql = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             JOIN class_fields cf0 ON cf0.class_descriptor = c.descriptor \
             JOIN class_fields cf1 ON cf1.class_descriptor = c.descriptor \
             WHERE instr(c.descriptor, 'Lcom/tencent/mm/storage/') = 1 \
               AND c.interface_count >= 0 AND c.interface_count <= 2 \
               AND ((cf0.access_flags & 8) = 8) AND cf0.field_name = 'field_UserName' \
               AND instr(cf0.field_descriptor, ':Ljava/lang/String;') > 0 \
               AND cf1.field_name = 'field_StatusID' \
               AND NOT (cf0.file_id = cf1.file_id AND cf0.field_idx = cf1.field_idx) \
             ORDER BY c.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "bare class declared-field units must use the fast path"
        );
    }

    #[test]
    fn accepts_bare_class_field_count_lookup() {
        let sql = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE c.field_count >= 0 AND c.field_count <= 1 \
             ORDER BY c.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "field_count class lookup must use the fast path"
        );
    }

    #[test]
    fn accepts_method_using_numbers_double_filter() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_using_numbers mn0 ON mn0.method = m.descriptor \
             WHERE mn0.file_id = m.file_id AND mn0.method_idx = m.method_idx \
               AND mn0.double_value = 0.5 AND m.class_descriptor = 'Lcom/tencent/mm/feature/avatar/w;' \
               AND m.return_descriptor = 'V' \
               AND m.param_descriptors = 'Landroid/widget/ImageView;,Ljava/lang/String;' \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "double using_numbers query must use the fast path"
        );
    }

    #[test]
    fn accepts_method_base_field_access_relation_lookup() {
        // New shape used by WeKit's batched field-access relation fetch: base methods
        // joined to method_field_accesses, selecting the access method descriptor.
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_field_accesses fa0 ON fa0.method = m.descriptor \
             WHERE fa0.field = 'Lcom/test/Alpha;->count:I' \
               AND fa0.file_id = m.file_id \
               AND fa0.method_idx = m.method_idx \
               AND fa0.using_type = 'get' \
             ORDER BY m.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "method-base field access query must use the fast path"
        );
    }

    #[test]
    fn accepts_access_flag_class_lookup_with_superclass() {
        let sql = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN classes c ON c.descriptor = cm.class_descriptor \
             WHERE cm.name = 'onCreate' AND c.file_id = cm.file_id \
               AND c.class_idx = cm.class_idx \
               AND c.superclass_descriptor = 'Landroid/app/Activity;' \
               AND ((c.access_flags & 1024) = 1024) \
             ORDER BY cm.class_descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(fast.is_some());
    }

    #[test]
    fn accepts_multiple_field_access_units() {
        let sql = "SELECT DISTINCT f.descriptor AS descriptor FROM fields f \
             JOIN method_field_accesses fa0 ON fa0.field = f.descriptor \
             JOIN methods fm0 ON fm0.descriptor = fa0.method \
             JOIN method_strings ms1 ON ms1.method = fm0.descriptor \
             JOIN method_field_accesses fa1 ON fa1.field = f.descriptor \
             JOIN methods fm1 ON fm1.descriptor = fa1.method \
             JOIN method_strings ms3 ON ms3.method = fm1.descriptor \
             WHERE f.class_descriptor = 'Lcom/tencent/mm/plugin/sns/ui/improve/cover/SnsImproveCoverLayout;' \
               AND f.type_descriptor = 'I' AND fa0.file_id = f.file_id \
               AND fa0.field_idx = f.field_idx AND fm0.file_id = fa0.file_id \
               AND fm0.method_idx = fa0.method_idx AND fa0.using_type = 'get' \
               AND ms1.file_id = fm0.file_id AND ms1.method_idx = fm0.method_idx \
               AND ms1.value = 'onBackPressed' AND fa1.file_id = f.file_id \
               AND fa1.field_idx = f.field_idx AND fm1.file_id = fa1.file_id \
               AND fm1.method_idx = fa1.method_idx AND fa1.using_type = 'put' \
               AND ms3.file_id = fm1.file_id AND ms3.method_idx = fm1.method_idx \
               AND ms3.value = 'updateViewHeight' \
             ORDER BY f.descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("multiple field access units should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_mixed_class_literal_and_injective_units() {
        let sql = "SELECT DISTINCT cm.class_descriptor AS d FROM methods cm \
             JOIN method_strings ms0 ON ms0.method = cm.descriptor \
             JOIN methods cm1 ON cm1.class_descriptor = cm.class_descriptor \
             JOIN method_strings ms2 ON ms2.method = cm1.descriptor \
             JOIN methods cm3 ON cm3.class_descriptor = cm.class_descriptor \
             JOIN method_strings ms4 ON ms4.method = cm3.descriptor \
             WHERE ms0.file_id = cm.file_id AND ms0.method_idx = cm.method_idx \
               AND ms0.value = 'activity' AND cm1.file_id = cm.file_id \
               AND cm1.class_idx = cm.class_idx AND ms2.file_id = cm1.file_id \
               AND ms2.method_idx = cm1.method_idx AND ms2.value = 'context' \
               AND cm3.file_id = cm.file_id AND cm3.class_idx = cm.class_idx \
               AND ms4.file_id = cm3.file_id AND ms4.method_idx = cm3.method_idx \
               AND ms4.value = 'itemView' \
               AND NOT (cm1.file_id = cm3.file_id AND cm1.method_idx = cm3.method_idx) \
             ORDER BY cm.class_descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("mixed literal and injective units should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_declared_class_literal_units() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN methods ccm0 ON ccm0.class_descriptor = m.class_descriptor \
             JOIN method_strings ms0 ON ms0.method = ccm0.descriptor \
             WHERE m.name = 'target' AND ccm0.file_id = m.file_id \
               AND ccm0.class_idx = m.class_idx AND ms0.file_id = ccm0.file_id \
               AND ms0.method_idx = ccm0.method_idx AND ms0.value = 'marker' \
             ORDER BY m.descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("declaredClass literal unit should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_two_declared_class_literal_units_with_numbers() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_strings ms0 ON ms0.method = m.descriptor \
             JOIN methods ccm0 ON ccm0.class_descriptor = m.class_descriptor \
             JOIN method_strings ms1 ON ms1.method = ccm0.descriptor \
             JOIN methods ccm1 ON ccm1.class_descriptor = m.class_descriptor \
             JOIN method_using_numbers mn2 ON mn2.method = ccm1.descriptor \
             WHERE ms0.file_id = m.file_id AND ms0.method_idx = m.method_idx \
               AND ms0.value = 'outer' AND ccm0.file_id = m.file_id \
               AND ccm0.class_idx = m.class_idx AND ms1.file_id = ccm0.file_id \
               AND ms1.method_idx = ccm0.method_idx AND ms1.value = 'first' \
               AND ccm1.file_id = m.file_id AND ccm1.class_idx = m.class_idx \
               AND mn2.file_id = ccm1.file_id AND mn2.method_idx = ccm1.method_idx \
               AND mn2.long_value = 57 \
             ORDER BY m.descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("two class literal units should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_super_class_constraint_on_methods_class_query() {
        let sql = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN classes cc ON cc.descriptor = cm.class_descriptor \
             JOIN methods scm0 ON scm0.class_descriptor = cc.superclass_descriptor \
             JOIN method_strings ms0 ON ms0.method = scm0.descriptor \
             WHERE cm.name = 'target' AND cc.file_id = cm.file_id \
               AND cc.class_idx = cm.class_idx AND ms0.file_id = scm0.file_id \
               AND ms0.method_idx = scm0.method_idx AND ms0.value = 'marker' \
             ORDER BY cm.class_descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("superClass constraint should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_super_class_constraint_on_bare_class_query() {
        let sql = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             JOIN methods scm0 ON scm0.class_descriptor = c.superclass_descriptor \
             JOIN method_strings ms0 ON ms0.method = scm0.descriptor \
             WHERE ms0.file_id = scm0.file_id AND ms0.method_idx = scm0.method_idx \
               AND ms0.value = 'marker' \
             ORDER BY c.descriptor;";
        let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
            .expect("bare superClass constraint should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_case_sensitive_instr_predicates() {
        let contains_sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_strings ms0 ON ms0.method = m.descriptor \
             WHERE ms0.file_id = m.file_id AND ms0.method_idx = m.method_idx \
               AND instr(ms0.value, 'MicroMsg.ConversationStorage') > 0 \
             ORDER BY m.descriptor;";
        assert!(
            try_fast_descriptor_lookup(&parse(contains_sql), &Dataset::default(), None).is_some()
        );
        let prefix_sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_strings ms0 ON ms0.method = m.descriptor \
             WHERE ms0.file_id = m.file_id AND ms0.method_idx = m.method_idx \
               AND instr(ms0.value, 'updateUnread') = 1 \
               AND instr(m.class_descriptor, 'Lcom/tencent/mm/storage/') = 1 \
             ORDER BY m.descriptor;";
        assert!(
            try_fast_descriptor_lookup(&parse(prefix_sql), &Dataset::default(), None).is_some()
        );
        let suffix_sql = "SELECT DISTINCT f.descriptor AS descriptor FROM fields f \
             JOIN method_field_accesses fa0 ON fa0.field = f.descriptor \
             JOIN methods fm0 ON fm0.descriptor = fa0.method \
             JOIN method_strings ms0 ON ms0.method = fm0.descriptor \
             WHERE f.class_descriptor = 'Lcom/tencent/mm/ui/Foo;' \
               AND fa0.file_id = f.file_id AND fa0.field_idx = f.field_idx \
               AND fm0.file_id = fa0.file_id AND fm0.method_idx = fa0.method_idx \
               AND fa0.using_type = 'get' AND ms0.file_id = fm0.file_id \
               AND ms0.method_idx = fm0.method_idx \
               AND substr(ms0.value, -5) = 's.xml' \
             ORDER BY f.descriptor;";
        assert!(
            try_fast_descriptor_lookup(&parse(suffix_sql), &Dataset::default(), None).is_some()
        );
    }

    #[test]
    fn rejects_mismatched_suffix_length() {
        let sql = "SELECT DISTINCT m.descriptor AS method FROM methods m \
             JOIN method_strings ms0 ON ms0.method = m.descriptor \
             WHERE ms0.file_id = m.file_id AND ms0.method_idx = m.method_idx \
               AND substr(ms0.value, -4) = 's.xml' \
             ORDER BY m.descriptor;";
        assert!(try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None).is_none());
    }

    #[test]
    fn accepts_escaped_like_method_lookup() {
        let query = parse(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             JOIN method_strings ms0 ON ms0.method = m.descriptor \
             WHERE ms0.file_id = m.file_id AND ms0.method_idx = m.method_idx \
               AND ms0.value LIKE '%50\\%%' ESCAPE '\\' \
             ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("fast path should accept escaped LIKE patterns");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_access_flag_method_lookup() {
        let query = parse(
            "SELECT DISTINCT m.descriptor AS descriptor FROM methods m \
             WHERE m.name = 'onCreate' AND (m.access_flags & 8) = 8 \
             ORDER BY m.descriptor LIMIT 1;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("fast path should accept bitwise flag predicates");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_access_flag_bare_class_lookup() {
        let query = parse(
            "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE (c.access_flags & 1024) = 1024 \
             ORDER BY c.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("fast path should accept class flag predicates");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_injective_nested_method_class_lookup() {
        // Canonical shape for DexKit methods{add{}} injective matching: the
        // NOT (identity mismatch) conditions must be understood by the fast path.
        let query = parse(
            "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN method_strings ms1 ON ms1.method = cm.descriptor \
             JOIN methods cm2 ON cm2.class_descriptor = cm.class_descriptor \
             JOIN method_strings ms3 ON ms3.method = cm2.descriptor \
             WHERE ms1.file_id = cm.file_id AND ms1.method_idx = cm.method_idx \
               AND ms1.value = 'Int' AND cm2.file_id = cm.file_id \
               AND cm2.class_idx = cm.class_idx AND ms3.file_id = cm2.file_id \
               AND ms3.method_idx = cm2.method_idx AND ms3.value = 'Int' \
               AND NOT (cm.file_id = cm2.file_id AND cm.method_idx = cm2.method_idx) \
             ORDER BY cm.class_descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("fast path should accept the canonical shape");
        assert!(result.is_ok());
    }

    #[test]
    fn injective_assignment_requires_distinct_methods() {
        let mut used = HashSet::new();
        assert!(assign_distinct(
            0,
            &[vec![1, 2], vec![1], vec![3, 1, 4]],
            &mut used
        ));
        let mut used = HashSet::new();
        assert!(!assign_distinct(0, &[vec![1], vec![1], vec![1]], &mut used));
        let mut used = HashSet::new();
        assert!(!assign_distinct(0, &[vec![], vec![1]], &mut used));
    }

    #[test]
    fn accepts_case_sensitive_class_descriptor_match_modes() {
        // Canonical T3 forms: instr()/substr() over methods.class_descriptor.
        for (sql, label) in [
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE instr(m.class_descriptor, 'Lcom/tencent/mm/plugin') = 1 \
                 ORDER BY m.descriptor;",
                "startsWith",
            ),
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE instr(m.class_descriptor, 'pluginsdk') > 0 \
                 ORDER BY m.descriptor;",
                "contains",
            ),
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE substr(m.class_descriptor, -5) = 'Info;' \
                 ORDER BY m.descriptor;",
                "endsWith",
            ),
        ] {
            let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
                .unwrap_or_else(|| panic!("class name {label} should use the fast path"));
            assert!(result.is_ok(), "class name {label}");
        }
    }

    #[test]
    fn accepts_case_sensitive_return_descriptor_match_modes() {
        for (sql, label) in [
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE instr(m.return_descriptor, 'Ljava/util/List') = 1 \
                 ORDER BY m.descriptor;",
                "startsWith",
            ),
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE instr(m.return_descriptor, 'List') > 0 \
                 ORDER BY m.descriptor;",
                "contains",
            ),
            (
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE substr(m.return_descriptor, -5) = 'List;' \
                 ORDER BY m.descriptor;",
                "endsWith",
            ),
        ] {
            let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
                .unwrap_or_else(|| panic!("return name {label} should use the fast path"));
            assert!(result.is_ok(), "return name {label}");
        }
    }

    #[test]
    fn accepts_case_sensitive_superclass_descriptor_match_modes() {
        // classes alias joined from a methods-class projection.
        let class_unit = parse(
            "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN classes cc ON cc.descriptor = cm.class_descriptor \
             WHERE instr(cc.superclass_descriptor, 'Landroid/app/Activity') = 1 \
             ORDER BY cm.class_descriptor;",
        );
        let result = try_fast_descriptor_lookup(&class_unit, &Dataset::default(), None)
            .expect("superclass startsWith should use the fast path");
        assert!(result.is_ok());

        // Bare classes query with contains/endsWith superclass predicates.
        for sql in [
            "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE instr(c.superclass_descriptor, 'Activity') > 0 \
             ORDER BY c.descriptor;",
            "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE substr(c.superclass_descriptor, -5) = 'Base;' \
             ORDER BY c.descriptor;",
        ] {
            let result = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None)
                .expect("superclass name mode should use the fast path");
            assert!(result.is_ok());
        }
    }

    #[test]
    fn accepts_combined_name_match_modes() {
        let result = try_fast_descriptor_lookup(
            &parse(
                "SELECT DISTINCT m.descriptor AS method FROM methods m \
                 WHERE instr(m.class_descriptor, 'Lcom/tencent/mm/plugin') = 1 \
                   AND instr(m.return_descriptor, 'List') > 0 \
                   AND substr(m.class_descriptor, -5) = 'Menu;' \
                 ORDER BY m.descriptor;",
            ),
            &Dataset::default(),
            None,
        )
        .expect("combined name modes should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_class_projection_without_predicates() {
        // Regression guard: class-projected lookups with no method-unit filter
        // enumerate referenced classes from the method ids (the generic scan
        // also exposes classes that are only referenced, without definitions).
        let result = try_fast_descriptor_lookup(
            &parse(
                "SELECT DISTINCT m.class_descriptor AS descriptor FROM methods m \
                 ORDER BY m.class_descriptor LIMIT 3;",
            ),
            &Dataset::default(),
            None,
        )
        .expect("bare class projection should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_name_modes_on_unsupported_columns() {
        // T3 shapes for the plain method name column stay on the generic path.
        let dataset = Dataset::default();
        let sql = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m \
             WHERE instr(m.name, 'onClick') > 0 ORDER BY m.descriptor;",
        );
        assert!(try_fast_descriptor_lookup(&sql, &dataset, None).is_none());
    }

    #[test]
    fn accepts_param_types_match_pattern_predicate() {
        let query = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE m.name = 'target' AND param_types_match(m.param_descriptors, 'I,J,?,?')              ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("param_types_match should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_param_types_match_equals_one_form() {
        // The bare boolean call is canonical, but the fast path also understands
        // param_types_match(...) = 1.
        let query = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE param_types_match(m.param_descriptors, '?') = 1              ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("param_types_match = 1 should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_param_count_inclusive_range() {
        let query = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE m.name = 'target' AND m.param_count >= 10 AND m.param_count <= 11              ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("inclusive param_count ranges should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_param_count_strict_bounds() {
        let query = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE m.param_count > 3 AND m.param_count < 5 ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("strict integer bounds should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_param_pattern_on_class_constraint_unit() {
        // declaredClass { paramTypes(...) } shape: the pattern belongs to the
        // nested methods alias, not the projected alias.
        let query = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              JOIN methods ccm0 ON ccm0.class_descriptor = m.class_descriptor              WHERE m.name = 'target' AND ccm0.file_id = m.file_id                AND ccm0.class_idx = m.class_idx                AND param_types_match(ccm0.param_descriptors, '?,java.lang.String')              ORDER BY m.descriptor;",
        );
        let result = try_fast_descriptor_lookup(&query, &Dataset::default(), None)
            .expect("class constraint unit pattern should use the fast path");
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_unsupported_param_pattern_forms() {
        let dataset = Dataset::default();
        // Comparing the truth value against anything but 1 must stay on the
        // generic path.
        let equals_zero = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE param_types_match(m.param_descriptors, 'I') = 0 ORDER BY m.descriptor;",
        );
        assert!(try_fast_descriptor_lookup(&equals_zero, &dataset, None).is_none());
        // The pattern must be a literal.
        let dynamic_pattern = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE param_types_match(m.param_descriptors, m.name) ORDER BY m.descriptor;",
        );
        assert!(try_fast_descriptor_lookup(&dynamic_pattern, &dataset, None).is_none());
        // Unknown text bounds fall back to the generic executor.
        let text_bound = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m              WHERE m.name > 3 ORDER BY m.descriptor;",
        );
        assert!(try_fast_descriptor_lookup(&text_bound, &dataset, None).is_none());
    }

    #[test]
    fn accepts_class_interface_units() {
        // Shape emitted by WeKit's class-level interfaceSpec { } matcher on the
        // methods-anchored class path: injective class_interfaces joins distinct by ordinal.
        let sql = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN method_strings ms0 ON ms0.method = cm.descriptor \
             JOIN class_interfaces ci0 ON ci0.class_idx = cm.class_idx \
             JOIN class_interfaces ci1 ON ci1.class_idx = cm.class_idx \
             WHERE ms0.file_id = cm.file_id AND ms0.method_idx = cm.method_idx \
               AND instr(ms0.value, 'activity') > 0 \
               AND ci0.file_id = cm.file_id \
               AND ci0.interface_descriptor = 'Landroid/app/Activity;' \
               AND ci1.file_id = cm.file_id \
               AND instr(ci1.interface_descriptor, 'Landroid/view') = 1 \
               AND NOT (ci0.file_id = ci1.file_id AND ci0.ordinal = ci1.ordinal) \
             ORDER BY cm.class_descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "class interface units must use the fast path"
        );
    }

    #[test]
    fn accepts_bare_class_interface_units() {
        let sql = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             JOIN class_interfaces ci0 ON ci0.class_idx = c.class_idx \
             JOIN class_interfaces ci1 ON ci1.class_idx = c.class_idx \
             WHERE ci0.file_id = c.file_id \
               AND ci0.interface_descriptor = 'Landroid/app/Activity;' \
               AND ci1.file_id = c.file_id \
               AND instr(ci1.interface_descriptor, 'Landroid/view') = 1 \
               AND NOT (ci0.file_id = ci1.file_id AND ci0.ordinal = ci1.ordinal) \
             ORDER BY c.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "bare class interface units must use the fast path"
        );
    }

    #[test]
    fn accepts_class_method_count_with_interface_count() {
        // Shape emitted by WeKit's class methodCount matcher on the methods-anchored class path;
        // interfaceCount joins the same classes alias.
        let sql = "SELECT DISTINCT cm.class_descriptor AS descriptor FROM methods cm \
             JOIN classes c ON c.descriptor = cm.class_descriptor \
             WHERE cm.name = 'onSceneEnd' AND cm.param_count = 4 \
               AND ((c.access_flags & 1536) = 1536) \
               AND c.file_id = cm.file_id AND c.class_idx = cm.class_idx \
               AND c.interface_count = 0 AND c.method_count = 1 \
             ORDER BY cm.class_descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "class method_count/interface_count predicates must use the fast path"
        );
    }

    #[test]
    fn accepts_bare_class_method_count() {
        let sql = "SELECT DISTINCT c.descriptor AS descriptor FROM classes c \
             WHERE c.descriptor = 'Lcom/tencent/mm/ui/LauncherUI;' \
               AND c.method_count = 1 ORDER BY c.descriptor;";
        let fast = try_fast_descriptor_lookup(&parse(sql), &Dataset::default(), None);
        assert!(
            fast.is_some(),
            "bare class method_count lookup must use the fast path"
        );
    }

    #[test]
    fn rejects_shapes_outside_descriptor_lookups() {
        let dataset = Dataset::default();
        let without_distinct =
            parse("SELECT m.descriptor AS method FROM methods m ORDER BY m.descriptor;");
        assert!(try_fast_descriptor_lookup(&without_distinct, &dataset, None).is_none());
        let unknown_projection =
            parse("SELECT DISTINCT m.name AS name FROM methods m ORDER BY m.name;");
        assert!(try_fast_descriptor_lookup(&unknown_projection, &dataset, None).is_none());
        let unsupported_join = parse(
            "SELECT DISTINCT m.descriptor AS method FROM methods m JOIN method_calls mc ON mc.method = m.descriptor ORDER BY m.descriptor;",
        );
        assert!(try_fast_descriptor_lookup(&unsupported_join, &dataset, None).is_none());
    }
}
