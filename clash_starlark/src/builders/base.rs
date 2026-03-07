//! Base policy value — the return type of `main()`.
//!
//! Wraps a v5 match tree JSON document.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::{NoSerialize, ProvidesStaticType, StarlarkValue, Trace, starlark_value};

/// A base policy value — the return type of `main()`.
///
/// Created by `_mt_policy()` which builds a v5 match tree document.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct BasePolicyValue {
    /// The v5 JSON document.
    #[allocative(skip)]
    pub base_doc: Option<JsonValue>,
    /// Default effect for unmatched requests.
    pub default_effect: String,
}

unsafe impl Trace<'_> for BasePolicyValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for BasePolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Policy(default={})", self.default_effect)
    }
}

starlark_simple_value!(BasePolicyValue);

#[starlark_value(type = "BasePolicyValue")]
impl<'v> StarlarkValue<'v> for BasePolicyValue {}
