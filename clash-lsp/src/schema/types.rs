//! Core schema types for the clash policy DSL surface.

#[derive(Debug, Clone)]
pub struct Schema {
    pub builtins: Vec<Builtin>,
}

#[derive(Debug, Clone)]
pub struct Builtin {
    pub name: &'static str,
    pub signature: &'static str,
    pub doc: &'static str,
}

impl Schema {
    pub fn lookup(&self, name: &str) -> Option<&Builtin> {
        self.builtins.iter().find(|b| b.name == name)
    }
}
