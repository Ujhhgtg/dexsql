//! Type-strict SQL equality keys and query-local compiled IN lists.
use super::{eval_scalar, RelRow, Scalar};
use sqlparser::ast::{
    Expr, Function, FunctionArg, FunctionArgExpr, FunctionArgumentList, FunctionArguments, Ident,
    ObjectName, UnaryOperator, Value,
};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

pub(super) const HASH_THRESHOLD: usize = 16;
const FUNCTION_NAME: &str = "\0dexsql_membership";
const SEMIJOIN_NAME: &str = "\0dexsql_semijoin";

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) enum Key {
    Null,
    Int(i64),
    Real(u64),
    Text(Arc<str>),
    Blob(Vec<u8>),
    InvalidReal(String),
}

/// NULL and NaN never match a non-NULL equality operand. Integral REALs share
/// the integer key only when conversion is exact and within the i64 range.
pub(super) fn key(value: &Scalar) -> Option<Key> {
    match value {
        Scalar::Null => None,
        Scalar::Real(text) if text.parse::<f64>().is_ok_and(f64::is_nan) => None,
        _ => Some(set_key(value)),
    }
}

/// Set and group identity retains NULL and canonical NaN as different keys.
/// Numeric identity otherwise matches equality/joins, including exact i64
/// boundaries and signed zero, without rounding integers through f64.
pub(super) fn set_key(value: &Scalar) -> Key {
    match value {
        Scalar::Null => Key::Null,
        Scalar::Int(value) => Key::Int(*value),
        Scalar::Text(value) => Key::Text(value.clone()),
        Scalar::Blob(value) => Key::Blob(value.clone()),
        Scalar::Real(text) => match text.parse::<f64>() {
            Ok(value) if value.is_nan() => Key::Real(f64::NAN.to_bits()),
            Ok(value) if exact_integer(value).is_some() => Key::Int(value as i64),
            Ok(value) => Key::Real(value.to_bits()),
            Err(_) => Key::InvalidReal(text.clone()),
        },
    }
}

fn exact_integer(value: f64) -> Option<i64> {
    // i64::MAX as f64 rounds to 2^63, so the upper bound must be exclusive.
    (value >= i64::MIN as f64 && value < -(i64::MIN as f64) && value.fract() == 0.0)
        .then_some(value as i64)
}

fn int_real_cmp(integer: i64, real: f64) -> Ordering {
    if real.is_nan() || real < i64::MIN as f64 {
        return Ordering::Greater;
    }
    if real >= -(i64::MIN as f64) {
        return Ordering::Less;
    }
    match integer.cmp(&(real as i64)) {
        Ordering::Equal => 0.0f64.partial_cmp(&real.fract()).unwrap_or(Ordering::Equal),
        order => order,
    }
}

/// Compare numeric values without rounding an integer through f64 first.
pub(super) fn numeric_cmp(left: &Scalar, right: &Scalar) -> Option<Ordering> {
    let real_cmp = |left: f64, right: f64| match (left.is_nan(), right.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
    };
    match (left, right) {
        (Scalar::Int(left), Scalar::Int(right)) => Some(left.cmp(right)),
        (Scalar::Int(left), Scalar::Real(right)) => Some(int_real_cmp(*left, right.parse().ok()?)),
        (Scalar::Real(left), Scalar::Int(right)) => {
            Some(int_real_cmp(*right, left.parse().ok()?).reverse())
        }
        (Scalar::Real(left), Scalar::Real(right)) => {
            Some(real_cmp(left.parse().ok()?, right.parse().ok()?))
        }
        _ => None,
    }
}

pub(super) fn equal(left: &Scalar, right: &Scalar) -> bool {
    match (left, right) {
        (Scalar::Null, Scalar::Null) => true,
        (Scalar::Text(left), Scalar::Text(right)) => left == right,
        (Scalar::Blob(left), Scalar::Blob(right)) => left == right,
        (Scalar::Int(_), Scalar::Int(_))
        | (Scalar::Int(_), Scalar::Real(_))
        | (Scalar::Real(_), Scalar::Int(_))
        | (Scalar::Real(_), Scalar::Real(_)) => {
            if [left, right].iter().any(|value| matches!(value, Scalar::Real(text) if text.parse::<f64>().is_ok_and(f64::is_nan))) {
                return false;
            }
            numeric_cmp(left, right).is_some_and(Ordering::is_eq)
                || matches!((left, right), (Scalar::Real(a), Scalar::Real(b)) if a == b && a.parse::<f64>().is_err())
        }
        _ => false,
    }
}

pub(super) fn result(
    found: bool,
    saw_null: bool,
    empty: bool,
    value: &Scalar,
    negated: bool,
) -> Scalar {
    if empty {
        return Scalar::Int(negated as i64);
    }
    if matches!(value, Scalar::Null) || (!found && saw_null) {
        return Scalar::Null;
    }
    Scalar::Int((found != negated) as i64)
}

struct Compiled {
    keys: HashSet<Key>,
    saw_null: bool,
    negated: bool,
    empty: bool,
}
impl Compiled {
    fn new(values: Vec<Scalar>, negated: bool) -> Self {
        let empty = values.is_empty();
        let saw_null = values.iter().any(|value| matches!(value, Scalar::Null));
        Self {
            keys: values.iter().filter_map(key).collect(),
            saw_null,
            negated,
            empty,
        }
    }
    fn evaluate(&self, value: &Scalar) -> Scalar {
        let found = key(value).is_some_and(|key| self.keys.contains(&key));
        result(found, self.saw_null, self.empty, value, self.negated)
    }
}

struct Semijoin {
    keys: HashSet<Vec<Key>>,
    negated: bool,
}

thread_local! {
    static COMPILED: RefCell<Vec<Compiled>> = const { RefCell::new(Vec::new()) };
    static SEMIJOINS: RefCell<Vec<Semijoin>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn register_rows(keys: HashSet<Vec<Key>>, negated: bool, values: Vec<Expr>) -> Expr {
    let index = SEMIJOINS.with(|sets| {
        let mut sets = sets.borrow_mut();
        let index = sets.len();
        sets.push(Semijoin { keys, negated });
        index
    });
    let mut args = vec![FunctionArg::Unnamed(FunctionArgExpr::Expr(
        super::scalar_literal(Scalar::Int(index as i64)),
    ))];
    args.extend(
        values
            .into_iter()
            .map(|expr| FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))),
    );
    Expr::Function(Function {
        name: ObjectName::from(vec![Ident::new(SEMIJOIN_NAME)]),
        uses_odbc_syntax: false,
        parameters: FunctionArguments::None,
        args: FunctionArguments::List(FunctionArgumentList {
            duplicate_treatment: None,
            args,
            clauses: Vec::new(),
        }),
        filter: None,
        null_treatment: None,
        over: None,
        within_group: Vec::new(),
    })
}

/// Nested query execution may register its own lists; truncate only entries
/// owned by this sink, on success, fallback, error, or unwind.
pub(super) struct Scope {
    start: usize,
    semijoins_start: usize,
}
impl Scope {
    pub(super) fn new() -> Self {
        Self {
            start: COMPILED.with(|sets| sets.borrow().len()),
            semijoins_start: SEMIJOINS.with(|sets| sets.borrow().len()),
        }
    }
    pub(super) fn compile(&self, expr: &mut Expr) {
        let Expr::InList {
            expr: value,
            list,
            negated,
        } = expr
        else {
            return;
        };
        if list.len() < HASH_THRESHOLD {
            return;
        }
        let Some(values) = list.iter().map(literal).collect::<Option<Vec<_>>>() else {
            return;
        };
        let index = COMPILED.with(|sets| {
            let mut sets = sets.borrow_mut();
            let index = sets.len();
            sets.push(Compiled::new(values, *negated));
            index
        });
        let value = std::mem::replace(value, Box::new(super::scalar_literal(Scalar::Null)));
        *expr = Expr::Function(Function {
            name: ObjectName::from(vec![Ident::new(FUNCTION_NAME)]),
            uses_odbc_syntax: false,
            parameters: FunctionArguments::None,
            args: FunctionArguments::List(FunctionArgumentList {
                duplicate_treatment: None,
                args: vec![
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(super::scalar_literal(
                        Scalar::Int(index as i64),
                    ))),
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(*value)),
                ],
                clauses: Vec::new(),
            }),
            filter: None,
            null_treatment: None,
            over: None,
            within_group: Vec::new(),
        });
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        COMPILED.with(|sets| sets.borrow_mut().truncate(self.start));
        SEMIJOINS.with(|sets| sets.borrow_mut().truncate(self.semijoins_start));
    }
}

fn literal(expr: &Expr) -> Option<Scalar> {
    match expr {
        Expr::Value(value) => super::scalar_from_value(value).ok(),
        Expr::Nested(value) => literal(value),
        Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus,
            expr: value,
        } if matches!(
            literal(value),
            Some(Scalar::Int(_) | Scalar::Real(_) | Scalar::Null)
        ) =>
        {
            eval_scalar(expr, &RelRow::default(), &[]).ok()
        }
        _ => None,
    }
}

/// Called before ordinary function-name formatting, so each probe allocates
/// no name or rendered-list strings. Evaluate the operand before borrowing TLS
/// to permit nested membership expressions.
pub(super) fn evaluate(
    function: &Function,
    row: &RelRow,
    group: &[RelRow],
) -> Option<Result<Scalar, String>> {
    if function.name.0.len() != 1 {
        return None;
    }
    let name = &function.name.0[0].as_ident()?.value;
    if name != FUNCTION_NAME && name != SEMIJOIN_NAME {
        return None;
    }
    Some((|| {
        let FunctionArguments::List(args) = &function.args else {
            return Err("invalid compiled membership".into());
        };
        let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(index)))) =
            args.args.first()
        else {
            return Err("invalid compiled membership arguments".into());
        };
        let Value::Number(index, _) = &index.value else {
            return Err("invalid compiled membership id".into());
        };
        let index = index
            .parse::<usize>()
            .map_err(|_| "invalid compiled membership id")?;
        if name == SEMIJOIN_NAME {
            let values = args.args[1..]
                .iter()
                .map(|arg| {
                    let FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) = arg else {
                        return Err("invalid semijoin key".to_owned());
                    };
                    eval_scalar(expr, row, group).map(|value| key(&value))
                })
                .collect::<Result<Option<Vec<_>>, _>>()?;
            return SEMIJOINS.with(|sets| {
                let sets = sets.borrow();
                let set = sets
                    .get(index)
                    .ok_or("compiled semijoin outside query scope")?;
                let found = values
                    .as_ref()
                    .is_some_and(|values| set.keys.contains(values));
                Ok(Scalar::Int((found != set.negated) as i64))
            });
        }
        let [_, FunctionArg::Unnamed(FunctionArgExpr::Expr(expr))] = args.args.as_slice() else {
            return Err("invalid compiled membership arguments".into());
        };
        let value = eval_scalar(expr, row, group)?;
        COMPILED.with(|sets| {
            sets.borrow()
                .get(index)
                .map(|set| set.evaluate(&value))
                .ok_or_else(|| "compiled membership outside query scope".to_owned())
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::super::{compare_scalar, eval_bool};
    use super::*;

    fn expression(sql: &str) -> Expr {
        let statement = sqlparser::parser::Parser::parse_sql(
            &sqlparser::dialect::SQLiteDialect {},
            &format!("SELECT {sql}"),
        )
        .unwrap()
        .remove(0);
        let sqlparser::ast::Statement::Query(query) = statement else {
            panic!()
        };
        let sqlparser::ast::SelectItem::UnnamedExpr(expr) =
            &query.body.as_select().unwrap().projection[0]
        else {
            panic!()
        };
        expr.clone()
    }
    fn real(value: &str) -> Scalar {
        Scalar::Real(value.to_owned())
    }

    #[test]
    fn equality_keys_preserve_types_and_exact_numeric_boundaries() {
        let values = [
            Scalar::Null,
            Scalar::Int(0),
            Scalar::Int(1),
            Scalar::Int(-1),
            Scalar::Int(9007199254740992),
            Scalar::Int(9007199254740993),
            Scalar::Int(i64::MIN),
            Scalar::Int(i64::MAX),
            real("0.0"),
            real("-0.0"),
            real("1.0"),
            real("1.5"),
            real("-1.5"),
            real("9007199254740992.0"),
            real("9007199254740994.0"),
            real("9223372036854775808.0"),
            real("-9223372036854775808.0"),
            real("inf"),
            real("-inf"),
            Scalar::text("0"),
            Scalar::text("1"),
            Scalar::text("1.0"),
            Scalar::Blob(vec![0x31]),
        ];
        for left in &values {
            for right in &values {
                if matches!(left, Scalar::Null) || matches!(right, Scalar::Null) {
                    continue;
                }
                assert_eq!(
                    left.sql_eq(right),
                    key(left) == key(right),
                    "{left:?} vs {right:?}"
                );
            }
        }
        assert!(!Scalar::Int(9007199254740993).sql_eq(&real("9007199254740992.0")));
        assert!(!Scalar::Int(i64::MAX).sql_eq(&real("9223372036854775808.0")));
        assert!(Scalar::Int(i64::MIN).sql_eq(&real("-9223372036854775808.0")));
        assert_eq!(key(&real("-0.0")), Some(Key::Int(0)));
        assert_eq!(key(&real("NaN")), None);
        assert!(!real("NaN").sql_eq(&real("NaN")));
    }

    #[test]
    fn ordering_uses_numeric_precision_and_sql_storage_types() {
        for (left, right, expected) in [
            (
                Scalar::Int(9007199254740993),
                real("9007199254740992.0"),
                Ordering::Greater,
            ),
            (
                Scalar::Int(9007199254740993),
                real("9007199254740994.0"),
                Ordering::Less,
            ),
            (
                Scalar::Int(i64::MAX),
                real("9223372036854775808.0"),
                Ordering::Less,
            ),
            (
                Scalar::Int(i64::MIN),
                real("-9223372036854775808.0"),
                Ordering::Equal,
            ),
            (Scalar::Int(-1), real("-1.5"), Ordering::Greater),
            (Scalar::Int(1), real("1.5"), Ordering::Less),
            (Scalar::text("1"), Scalar::Int(1), Ordering::Greater),
            (Scalar::text("2"), Scalar::Int(10), Ordering::Greater),
            (
                Scalar::Blob(vec![0x31]),
                Scalar::text("1"),
                Ordering::Greater,
            ),
            (Scalar::text("\n"), Scalar::text("a"), Ordering::Less),
        ] {
            assert_eq!(
                compare_scalar(&left, &right),
                expected,
                "{left:?} vs {right:?}"
            );
            assert_eq!(compare_scalar(&right, &left), expected.reverse());
        }
    }

    #[test]
    fn ordinary_membership_obeys_three_valued_logic_and_numeric_equality() {
        for (sql, expected) in [
            ("1 IN (1.0)", Scalar::Int(1)),
            ("'1' IN (1)", Scalar::Int(0)),
            ("'1.0' IN (1.0)", Scalar::Int(0)),
            ("1 IN (1,NULL)", Scalar::Int(1)),
            ("1 NOT IN (1,NULL)", Scalar::Int(0)),
            ("1 IN (2,NULL)", Scalar::Null),
            ("1 NOT IN (2,NULL)", Scalar::Null),
            ("NOT (1 IN (2,NULL))", Scalar::Null),
            ("NULL IN (2)", Scalar::Null),
            ("NULL NOT IN (2)", Scalar::Null),
            ("0.0 IN (-0.0)", Scalar::Int(1)),
            ("0 IN (-0.0)", Scalar::Int(1)),
            ("-0.0 IN (0)", Scalar::Int(1)),
            ("0 NOT IN (-0.0)", Scalar::Int(0)),
            ("9007199254740993 IN (9007199254740992.0)", Scalar::Int(0)),
            (
                "-9223372036854775808 IN (-9223372036854775808.0)",
                Scalar::Int(1),
            ),
            (
                "9223372036854775807 IN (9223372036854775808.0)",
                Scalar::Int(0),
            ),
            ("'1'=1", Scalar::Int(0)),
            ("1=1.0", Scalar::Int(1)),
            ("9007199254740993=9007199254740992.0", Scalar::Int(0)),
        ] {
            let expr = expression(sql);
            assert_eq!(
                eval_scalar(&expr, &RelRow::default(), &[]).unwrap(),
                expected,
                "{sql}"
            );
            assert_eq!(
                eval_bool(&expr, &RelRow::default(), &[]).unwrap(),
                expected.truthy(),
                "WHERE {sql}"
            );
        }
        for value in [Scalar::Null, Scalar::Int(1)] {
            for negated in [false, true] {
                let expr = Expr::InList {
                    expr: Box::new(super::super::scalar_literal(value.clone())),
                    list: Vec::new(),
                    negated,
                };
                assert_eq!(
                    eval_scalar(&expr, &RelRow::default(), &[]).unwrap(),
                    Scalar::Int(negated as i64)
                );
            }
        }
    }

    #[test]
    fn large_literal_membership_compiles_once_and_reuses_the_set() {
        let original = expression(&format!(
            "k NOT IN ({},NULL,'1',1.0,-0.0,-1)",
            (0..4096)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        let start = COMPILED.with(|sets| sets.borrow().len());
        let mut compiled = original.clone();
        {
            let scope = Scope::new();
            scope.compile(&mut compiled);
            assert!(matches!(compiled, Expr::Function(_)));
            COMPILED.with(|sets| {
                let sets = sets.borrow();
                assert_eq!(sets.len(), start + 1);
                assert_eq!(sets[start].keys.len(), 4098);
            });
            for value in [
                Scalar::Int(-2),
                Scalar::Int(-1),
                Scalar::Int(0),
                real("-0.0"),
                Scalar::Int(4095),
                Scalar::Int(4096),
                Scalar::text("1"),
                Scalar::text("2"),
                Scalar::Null,
            ] {
                let mut row = RelRow::default();
                row.put("t", "k", value);
                let expected = eval_scalar(&original, &row, &[]).unwrap();
                for _ in 0..20 {
                    assert_eq!(eval_scalar(&compiled, &row, &[]).unwrap(), expected);
                }
                assert_eq!(eval_bool(&compiled, &row, &[]).unwrap(), expected.truthy());
            }
            assert_eq!(COMPILED.with(|sets| sets.borrow().len()), start + 1);
            {
                let nested = Scope::new();
                let mut nested_expr = original.clone();
                nested.compile(&mut nested_expr);
                assert_eq!(COMPILED.with(|sets| sets.borrow().len()), start + 2);
            }
            assert_eq!(COMPILED.with(|sets| sets.borrow().len()), start + 1);
        }
        assert_eq!(COMPILED.with(|sets| sets.borrow().len()), start);
        let mut row = RelRow::default();
        row.put("t", "k", Scalar::Int(1));
        assert!(eval_scalar(&compiled, &row, &[])
            .unwrap_err()
            .contains("outside query scope"));
    }

    #[test]
    fn row_dependent_list_is_not_compiled() {
        let scope = Scope::new();
        let mut expr = expression(&format!(
            "k IN ({},other)",
            (0..16).map(|n| n.to_string()).collect::<Vec<_>>().join(",")
        ));
        scope.compile(&mut expr);
        assert!(matches!(expr, Expr::InList { .. }));
    }
}
