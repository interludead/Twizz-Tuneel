use crate::model::RouteRule;
use serde_json::Value;
pub fn analyze(target:&str,rules:&[RouteRule])->Value{crate::route_compiler::analyze(target,rules)}
pub fn conflicts(rules:&[RouteRule])->Value{crate::route_compiler::conflicts(rules)}
