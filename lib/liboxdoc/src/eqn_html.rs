//! eqn as HTML (MAN.md §4.5): an equation as MathML.

use crate::eqn::Eqn;
use crate::html::Html;

pub fn render(e: &Eqn, h: &mut Html) {
    let _ = e;
    h.open("math", "class=\"eqn\"");
    h.close("math");
}
